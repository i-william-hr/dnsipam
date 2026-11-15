#!/usr/bin/env python3
"""
dnsipam — core: the sqlite state, the nibble math for [REDACTED:internal-ipv6]/48,
the BIND zone renderer and the reload path.

Source of truth is the sqlite DB (data/ipam.db). The zone file named/ serves
is generated output: every mutation re-renders it, validates it with
named-checkzone and reloads the zone over rndc. Everything is stdlib-only,
like the zfs.inbox.li dashboard — there is no venv here and there must not be
one.
"""

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, 'data', 'ipam.db')
ZONE_DIR = os.path.join(BASE, 'named')

PREFIX_STR = '[REDACTED:internal-ipv6]/48'
PREFIX = ipaddress.IPv6Network(PREFIX_STR)
PREFIX_INT = int(PREFIX.network_address)
PREFIX_BITS = 48
ZONE = '8.c.4.1.0.e.4.9.3.0.a.2.ip6.arpa'
ZONE_FILE = os.path.join(ZONE_DIR, 'db.' + ZONE)

NS_RECORDS = ['ns3.inbox.li.', 'ns4.william.hr.']
SOA_MNAME = 'ns3.inbox.li.'
SOA_RNAME = 'hostmaster.inbox.li.'
SOA_REFRESH = 10800   # 3h
SOA_RETRY = 3600      # 1h
SOA_EXPIRE = 1209600  # 2 weeks
SOA_NEGATIVE = 600    # 10 minutes
RECORD_TTL_DEFAULT = 3600

RNDC = '/usr/sbin/rndc'
RNDC_KEY = '/etc/bind/rndc.key'
NAMED_CHECKZONE = '/usr/bin/named-checkzone'

KINDS = ('used', 'rented', 'reserved')

_write_lock = threading.Lock()
_last_serial = [0]


# --- canonical text / integers ------------------------------------------------

def canon_addr(addr):
    """Parse one address inside the /48. Returns canonical text or raises
    ValueError with a message meant for a human."""
    try:
        ip = ipaddress.IPv6Address(addr)
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError('not a valid IPv6 address: %r' % (addr,))
    if ip not in PREFIX:
        raise ValueError('%s is not inside %s' % (ip, PREFIX_STR))
    return str(ip)


def canon_prefix(addr, bits):
    """Parse one aligned sub-prefix of the /48. bits: 48..128. Returns
    (canonical text start address, bits) or raises ValueError."""
    bits = int(bits)
    if not PREFIX_BITS <= bits <= 128:
        raise ValueError('prefix length must be between /48 and /128')
    addr = canon_addr(addr)
    ip_int = int(ipaddress.IPv6Address(addr))
    size = 1 << (128 - bits)
    if ip_int % size:
        raise ValueError('%s/%d is not aligned — use the block start address'
                         % (addr, bits))
    return addr, bits


def _addr_int(addr):
    return int(ipaddress.IPv6Address(addr))


def _int_addr(n):
    return str(ipaddress.IPv6Address(n))


def ptr_owner_label(addr):
    """The 20-nibble reversed owner label for one address, relative to the
    zone origin. [REDACTED:internal-ipv6] -> 1.0.0.0.…0 (20 nibbles)."""
    nibbles = ipaddress.IPv6Address(addr).exploded.replace(':', '')
    tail = nibbles[12:]  # the /48 origin consumes the first 12
    return '.'.join(reversed(tail))


# --- database -----------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id         INTEGER PRIMARY KEY,
    address    TEXT UNIQUE NOT NULL,
    ptr        TEXT NOT NULL,
    ttl        INTEGER NOT NULL DEFAULT 3600,
    comment    TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS annotations (
    id         INTEGER PRIMARY KEY,
    prefix     TEXT NOT NULL,
    bits       INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    comment    TEXT NOT NULL DEFAULT '',
    price      TEXT NOT NULL DEFAULT '',
    renewal    TEXT NOT NULL DEFAULT '',
    contact    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (prefix, bits)
);
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY,
    ts     TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ok     INTEGER NOT NULL DEFAULT 1
);
"""


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def _init_db():
    with _connect() as conn:
        conn.executescript(SCHEMA)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def log_event(action, detail='', ok=True):
    try:
        with _connect() as conn:
            conn.execute('INSERT INTO events (ts, action, detail, ok) VALUES (?,?,?,?)',
                         (_now(), action, detail, 1 if ok else 0))
            conn.execute('DELETE FROM events WHERE id <= '
                         '(SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET 499)')
    except sqlite3.Error as exc:
        # The event log must never be the reason a mutation fails.
        print('event log failed: %s' % exc, flush=True)


# --- zone rendering + BIND -----------------------------------------------------

ZONE_HEADER = """\
; Generated by dnsipam from data/ipam.db — DO NOT EDIT BY HAND.
; The next record edit in the web UI (or `cli.py zone render`) rewrites this
; file from the database; manual changes here are lost without warning.
;
; Reverse zone for [REDACTED:internal-ipv6]/48, delegated by the ISP to
; ns3.inbox.li and ns4.william.hr (both names on this box).
$ORIGIN {zone}.
$TTL {ttl}
"""


def render_zone_text():
    """Render the full zone file text from the DB. Returns (text, serial)."""
    with _connect() as conn:
        records = conn.execute(
            'SELECT address, ptr, ttl FROM records ORDER BY address').fetchall()

    serial = int(time.time())
    if serial <= _last_serial[0]:
        serial = _last_serial[0] + 1

    lines = [ZONE_HEADER.format(zone=ZONE, ttl=RECORD_TTL_DEFAULT).rstrip('\n')]
    lines.append('@\tIN SOA\t%s %s (\n'
                 '\t\t%010d ; serial\n'
                 '\t\t%d ; refresh\n'
                 '\t\t%d ; retry\n'
                 '\t\t%d ; expire\n'
                 '\t\t%d ; negative TTL\n'
                 '\t)' % (SOA_MNAME, SOA_RNAME, serial,
                          SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_NEGATIVE))
    for ns in NS_RECORDS:
        lines.append('@\tIN NS\t%s' % ns)
    lines.append('')
    for rec in records:
        owner = ptr_owner_label(rec['address'])
        if rec['ttl'] != RECORD_TTL_DEFAULT:
            lines.append('%s\t%d\tIN PTR\t%s' % (owner, rec['ttl'], rec['ptr']))
        else:
            lines.append('%s\tIN PTR\t%s' % (owner, rec['ptr']))
    if records:
        lines.append('')
    return '\n'.join(lines), serial


def validate_ptr_target(ptr):
    """Strict RFC1123 hostname; returns the canonical form (lowercase, with
    trailing dot) or raises ValueError."""
    name = ptr.strip().rstrip('.').lower()
    if not name:
        raise ValueError('PTR target is empty')
    if len(name) > 253:
        raise ValueError('PTR target is longer than 253 characters')
    label_re = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
    labels = name.split('.')
    if len(labels) < 2:
        raise ValueError('PTR target must be a fully-qualified name with at '
                         'least two labels (e.g. host.inbox.li)')
    for label in labels:
        if not label_re.match(label):
            raise ValueError('not a valid hostname label: %r' % (label,))
    return name + '.'


def write_zone_and_reload():
    """Render, validate, write, reload. Runs under _write_lock. Returns
    (ok, message) — also logged to events."""
    text, serial = render_zone_text()
    tmp = ZONE_FILE + '.tmp'
    os.makedirs(ZONE_DIR, exist_ok=True)
    try:
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(text)
        os.chmod(tmp, 0o640)
        os.chown(tmp, -1, _bind_gid())

        check = subprocess.run([NAMED_CHECKZONE, '-q', ZONE, tmp],
                               capture_output=True, text=True, timeout=30)
        if check.returncode != 0:
            msg = 'named-checkzone rejected the generated zone: %s' % \
                (check.stderr.strip() or check.stdout.strip() or 'unknown error')
            log_event('zone.render', msg, ok=False)
            return False, msg

        os.replace(tmp, ZONE_FILE)
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        log_event('zone.render', 'write failed: %s' % exc, ok=False)
        return False, 'could not write the zone file: %s' % exc
    _last_serial[0] = serial
    return _rndc_reload('zone.render after edit, serial %d' % serial)


def _bind_gid():
    import grp
    return grp.getgrnam('bind').gr_gid


def _rndc(*args):
    return subprocess.run([RNDC, '-k', RNDC_KEY] + list(args),
                          capture_output=True, text=True, timeout=20)


def _rndc_reload(context):
    """rndc reload, falling back to reconfig (first load after named.conf
    gained the zone). Returns (ok, message); caller logs."""
    res = _rndc('reload', ZONE)
    if res.returncode != 0:
        res = _rndc('reconfig')
    if res.returncode != 0:
        msg = 'rndc failed: %s' % ((res.stderr or res.stdout).strip())
        log_event('zone.reload', msg, ok=False)
        return False, msg
    msg = 'zone reloaded (%s)' % context
    log_event('zone.reload', msg, ok=True)
    return True, msg


def bind_zone_status():
    """Live state from named: loaded serial etc. Never raises."""
    try:
        res = _rndc('zonestatus', ZONE)
        if res.returncode != 0:
            return {'ok': False, 'error': (res.stderr or res.stdout).strip()}
        out = {}
        for line in res.stdout.splitlines():
            if ':' in line:
                key, _, val = line.partition(':')
                out[key.strip().lower().replace(' ', '_')] = val.strip()
        return {'ok': True, **out}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {'ok': False, 'error': str(exc)}


# --- mutations -----------------------------------------------------------------

def record_add(address, ptr, ttl=None, comment=''):
    address = canon_addr(address)
    ptr = validate_ptr_target(ptr)
    ttl = int(ttl) if ttl is not None else RECORD_TTL_DEFAULT
    if not 60 <= ttl <= 604800:
        raise ValueError('TTL must be between 60 and 604800')
    comment = str(comment or '').strip()[:300]
    with _write_lock, _connect() as conn:
        existing = conn.execute('SELECT id FROM records WHERE address=?',
                                (address,)).fetchone()
        if existing:
            raise ValueError('a PTR record already exists for %s — edit or '
                             'delete it first' % address)
        conn.execute('INSERT INTO records (address, ptr, ttl, comment, updated_at) '
                     'VALUES (?,?,?,?,?)', (address, ptr, ttl, comment, _now()))
    ok, msg = write_zone_and_reload()
    log_event('record.add', '%s -> %s (%s)' % (address, ptr, msg), ok=ok)
    if not ok:
        raise RuntimeError(msg)
    return address


def record_update(rec_id, ptr=None, ttl=None, comment=None):
    with _write_lock, _connect() as conn:
        row = conn.execute('SELECT * FROM records WHERE id=?', (rec_id,)).fetchone()
        if not row:
            raise ValueError('no such record id %s' % rec_id)
        new_ptr = validate_ptr_target(ptr) if ptr is not None else row['ptr']
        new_ttl = int(ttl) if ttl is not None else row['ttl']
        if not 60 <= new_ttl <= 604800:
            raise ValueError('TTL must be between 60 and 604800')
        new_comment = row['comment'] if comment is None else str(comment).strip()[:300]
        conn.execute('UPDATE records SET ptr=?, ttl=?, comment=?, updated_at=? '
                     'WHERE id=?', (new_ptr, new_ttl, new_comment, _now(), rec_id))
    ok, msg = write_zone_and_reload()
    log_event('record.edit', '%s -> %s (%s)' % (row['address'], new_ptr, msg), ok=ok)
    if not ok:
        raise RuntimeError(msg)


def record_delete(rec_id):
    with _write_lock, _connect() as conn:
        row = conn.execute('SELECT * FROM records WHERE id=?', (rec_id,)).fetchone()
        if not row:
            raise ValueError('no such record id %s' % rec_id)
        conn.execute('DELETE FROM records WHERE id=?', (rec_id,))
    ok, msg = write_zone_and_reload()
    log_event('record.delete', '%s -> %s (%s)' % (row['address'], row['ptr'], msg), ok=ok)
    if not ok:
        raise RuntimeError(msg)


def annotation_add(prefix, bits, kind, label='', comment='', price='',
                   renewal='', contact=''):
    prefix, bits = canon_prefix(prefix, bits)
    if kind not in KINDS:
        raise ValueError('kind must be one of %s' % (', '.join(KINDS),))
    fields = {k: str(v or '').strip()[:300] for k, v in
              dict(label=label, comment=comment, price=price,
                   renewal=renewal, contact=contact).items()}
    with _write_lock, _connect() as conn:
        dup = conn.execute('SELECT id FROM annotations WHERE prefix=? AND bits=?',
                           (prefix, bits)).fetchone()
        if dup:
            raise ValueError('%s/%d is already annotated — edit or delete that '
                             'entry instead' % (prefix, bits))
        cur = conn.execute(
            'INSERT INTO annotations (prefix, bits, kind, label, comment, price, '
            'renewal, contact, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (prefix, bits, kind, fields['label'], fields['comment'],
             fields['price'], fields['renewal'], fields['contact'],
             _now(), _now()))
        ann_id = cur.lastrowid
    log_event('annotate.add', '%s/%d %s %s' % (prefix, bits, kind,
                                               fields['label']))
    return ann_id


def annotation_update(ann_id, **fields):
    allowed = ('kind', 'label', 'comment', 'price', 'renewal', 'contact')
    with _write_lock, _connect() as conn:
        row = conn.execute('SELECT * FROM annotations WHERE id=?', (ann_id,)).fetchone()
        if not row:
            raise ValueError('no such annotation id %s' % ann_id)
        sets, vals = [], []
        for key in allowed:
            if key in fields and fields[key] is not None:
                val = str(fields[key]).strip()[:300]
                if key == 'kind':
                    if val not in KINDS:
                        raise ValueError('kind must be one of %s' % (', '.join(KINDS),))
                sets.append('%s=?' % key)
                vals.append(val)
        if sets:
            vals.append(_now())
            vals.append(ann_id)
            conn.execute('UPDATE annotations SET %s, updated_at=? WHERE id=?'
                         % ', '.join(sets), vals)
    log_event('annotate.edit', '%s/%d' % (row['prefix'], row['bits']))


def annotation_delete(ann_id):
    with _write_lock, _connect() as conn:
        row = conn.execute('SELECT * FROM annotations WHERE id=?', (ann_id,)).fetchone()
        if not row:
            raise ValueError('no such annotation id %s' % ann_id)
        conn.execute('DELETE FROM annotations WHERE id=?', (ann_id,))
    log_event('annotate.delete', '%s/%d %s' % (row['prefix'], row['bits'], row['kind']))


# --- reads ---------------------------------------------------------------------

def records_list():
    with _connect() as conn:
        return [dict(r) for r in
                conn.execute('SELECT * FROM records ORDER BY address')]


def annotations_list():
    with _connect() as conn:
        rows = [dict(r) for r in conn.execute(
            'SELECT * FROM annotations ORDER BY bits DESC, prefix')]
    # integer forms for the UI math, computed once here
    for row in rows:
        row['_start'] = _addr_int(row['prefix'])
        row['_size'] = 1 << (128 - row['bits'])
    return rows


def events_list(limit=100):
    with _connect() as conn:
        return [dict(r) for r in conn.execute(
            'SELECT * FROM events ORDER BY id DESC LIMIT ?', (int(limit),))]


# --- IPAM math ------------------------------------------------------------------

def _ann_range(row):
    start = row['_start']
    return start, start + row['_size'] - 1


def _containing(anns, start, end):
    """Annotations that fully contain [start, end]."""
    return [a for a in anns
            if a['_start'] <= start and (a['_start'] + a['_size'] - 1) >= end]


def _inside(anns, start, end):
    """Annotations fully inside [start, end]."""
    return [a for a in anns
            if a['_start'] >= start and (a['_start'] + a['_size'] - 1) <= end]


def _overlapping(anns, start, end):
    return [a for a in anns
            if a['_start'] <= end and (a['_start'] + a['_size'] - 1) >= start]


def tree_children(prefix_addr, bits):
    """16 nibble-children of prefix/bits (bits must be < 128). Each child:
    covering annotation(s), count of annotations below, count of records below.
    """
    prefix_addr, bits = canon_prefix(prefix_addr, bits)
    if bits >= 128:
        raise ValueError('no children below /128')
    base = _addr_int(prefix_addr)
    child_size = 1 << (128 - bits - 4)
    anns = annotations_list()
    rec_ints = [(r['address'], _addr_int(r['address'])) for r in records_list()]

    children = []
    for i in range(16):
        cstart = base + i * child_size
        cend = cstart + child_size - 1
        covering = _containing(anns, cstart, cend)
        below = _inside(anns, cstart, cend)
        recs_below = 0
        for _, rint in rec_ints:
            if cstart <= rint <= cend:
                recs_below += 1
        children.append({
            'prefix': _int_addr(cstart),
            'bits': bits + 4,
            'nibble': format(i, 'x'),
            'covering': [{k: a[k] for k in ('id', 'kind', 'label', 'comment',
                                            'price', 'renewal', 'contact')}
                         for a in covering],
            'annotations_below': len(below),
            'records_below': recs_below,
        })
    return children


def node_detail(prefix_addr, bits):
    """Everything known about one node: annotations here/above/below,
    records here or within (small ranges only)."""
    prefix_addr, bits = canon_prefix(prefix_addr, bits)
    start = _addr_int(prefix_addr)
    size = 1 << (128 - bits)
    end = start + size - 1
    anns = annotations_list()

    out = {
        'prefix': prefix_addr,
        'bits': bits,
        'here': [{k: a[k] for k in ('id', 'kind', 'label', 'comment', 'price',
                                    'renewal', 'contact', 'created_at',
                                    'updated_at')}
                 for a in anns if a['_start'] == start and a['bits'] == bits],
        'covering': [{k: a[k] for k in ('id', 'kind', 'label', 'comment')}
                     for a in _containing(anns, start, end) if a['bits'] != bits],
        'below': [{k: a[k] for k in ('id', 'prefix', 'bits', 'kind', 'label',
                                     'comment', 'price', 'renewal', 'contact')}
                  for a in sorted(_inside(anns, start, end),
                                  key=lambda a: (a['bits'], a['_start']))],
        'records': [],
    }
    # Records within this node, but only if the node is small enough to be a
    # list rather than a /48. For a /128 that is the single address itself.
    if size <= 4096:
        rec_ints = [(_addr_int(r['address']), r) for r in records_list()]
        out['records'] = [dict(r) for rint, r in sorted(rec_ints)
                          if start <= rint <= end]
    return out


def free_blocks(bits, limit=100):
    """Aligned free blocks of requested size: no annotation overlaps them.
    Scans from the start of the /48 and stops once `limit` free blocks are
    found (the /48 holds 2**80 addresses — an exhaustive walk is not a thing).
    """
    prefix_addr, bits = canon_prefix(PREFIX_STR.split('/')[0], bits)
    block_size = 1 << (128 - bits)
    max_index = 1 << (bits - PREFIX_BITS) if bits >= PREFIX_BITS else 1
    anns = annotations_list()
    free = []
    i = 0
    while i < max_index and len(free) < limit:
        start = PREFIX_INT + i * block_size
        end = start + block_size - 1
        if not _overlapping(anns, start, end):
            free.append({'prefix': _int_addr(start), 'bits': bits})
        i += 1
    scanned = i
    total = max_index
    return {'blocks': free, 'total_blocks': total,
            'scanned': scanned, 'complete': scanned >= total}


def overview():
    anns = annotations_list()
    recs = records_list()

    # /64 coverage: how many of the 65536 /64s are claimed by annotations
    covered64 = set()
    for a in anns:
        s, e = _ann_range(a)
        first = (s >> 64) << 64
        last = (e >> 64) << 64
        n = int((last - first) >> 64) + 1
        if n <= 1 << 20:  # sanity: a stray /48-wide annotation would be 1 entry anyway
            for k in range(n):
                covered64.add(first + (k << 64))
        else:
            covered64.add(first)
    free64 = (1 << 16) - len(covered64)

    by_kind = {k: 0 for k in KINDS}
    for a in anns:
        by_kind[a['kind']] = by_kind.get(a['kind'], 0) + 1

    return {
        'zone': ZONE,
        'prefix': PREFIX_STR,
        'nameservers': NS_RECORDS,
        'records': len(recs),
        'annotations': len(anns),
        'annotations_by_kind': by_kind,
        'total_64s': 1 << 16,
        'free_64s': free64,
        'bind': bind_zone_status(),
        'events': events_list(10),
    }
