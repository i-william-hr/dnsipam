#!/usr/bin/env python3
"""
dnsipam CLI — the same operations the web UI offers, from the shell.

Use it for seeding, scripting and emergencies; every mutation still goes
through the zone renderer and rndc reload exactly like the web UI does.

  cli.py records list
  cli.py records add [REDACTED:internal-ipv6] moses.inbox.li [--ttl 3600] [--comment ...]
  cli.py records delete [REDACTED:internal-ipv6]
  cli.py annotations list
  cli.py annotations add [REDACTED:internal-ipv6]/64 used --label "NL" --comment ...
  cli.py annotations delete [REDACTED:internal-ipv6]/64
  cli.py free --bits 64
  cli.py zone render        (re-render + reload without any change)
  cli.py status
"""

import argparse
import sys

import ipam


def cmd_records(args):
    if args.op == 'add':
        address = ipam.record_add(args.address, args.ptr, args.ttl, args.comment)
        print('added PTR %s -> %s' % (address, args.ptr))
    elif args.op == 'delete':
        recs = {r['address']: r for r in ipam.records_list()}
        if args.address not in recs:
            sys.exit('no PTR record for %s' % args.address)
        ipam.record_delete(recs[args.address]['id'])
        print('deleted PTR for %s' % args.address)
    else:
        recs = ipam.records_list()
        print('%-42s %-40s %-6s %s' % ('address', 'PTR', 'TTL', 'comment'))
        for r in recs:
            print('%-42s %-40s %-6s %s' % (r['address'], r['ptr'], r['ttl'],
                                           r['comment']))
        print('%d record(s)' % len(recs))


def _find_annotation(prefix, bits):
    prefix, bits = ipam.canon_prefix(prefix, bits)
    for a in ipam.annotations_list():
        if a['prefix'] == prefix and a['bits'] == bits:
            return a
    return None


def cmd_annotations(args):
    if args.op == 'add':
        ann_id = ipam.annotation_add(args.prefix.split('/')[0],
                                     args.prefix.split('/')[1],
                                     args.kind, args.label, args.comment,
                                     args.price, args.renewal, args.contact)
        print('annotation %d saved' % ann_id)
    elif args.op == 'delete':
        bits = 64
        prefix = args.prefix
        if '/' in args.prefix:
            prefix, _, bits = args.prefix.partition('/')
            bits = int(bits)
        ann = _find_annotation(prefix, bits)
        if not ann:
            sys.exit('no annotation for %s' % args.prefix)
        ipam.annotation_delete(ann['id'])
        print('deleted annotation %d (%s/%d)' % (ann['id'], ann['prefix'], ann['bits']))
    else:
        anns = ipam.annotations_list()
        for a in anns:
            print('%s/%d  %-8s  %-24s price=%s renewal=%s contact=%s' % (
                a['prefix'], a['bits'], a['kind'], a['label'],
                a['price'] or '-', a['renewal'] or '-', a['contact'] or '-'))
            if a['comment']:
                print('%46s %s' % ('', a['comment']))
        print('%d annotation(s)' % len(anns))


def cmd_free(args):
    out = ipam.free_blocks(args.bits)
    for b in out['blocks'][:30]:
        print('%s/%d' % (b['prefix'], b['bits']))
    print('%d free block(s) shown of %s total %s/%d block(s) in the /48'
          % (min(len(out['blocks']), 30),
             'all' if out['complete'] else 'first-scan',
             'network', args.bits))


def cmd_zone(args):
    ok, msg = ipam.write_zone_and_reload()
    print(('OK: ' if ok else 'FAILED: ') + msg)
    sys.exit(0 if ok else 1)


def cmd_status(args):
    import json
    print(json.dumps(ipam.overview(), indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    rec = sub.add_parser('records')
    rec_sub = rec.add_subparsers(dest='op', required=True)
    rec_list = rec_sub.add_parser('list')
    rec_add = rec_sub.add_parser('add')
    rec_add.add_argument('address')
    rec_add.add_argument('ptr')
    rec_add.add_argument('--ttl', type=int, default=None)
    rec_add.add_argument('--comment', default='')
    rec_del = rec_sub.add_parser('delete')
    rec_del.add_argument('address')
    rec.set_defaults(func=cmd_records)

    ann = sub.add_parser('annotations')
    ann_sub = ann.add_subparsers(dest='op', required=True)
    ann_list = ann_sub.add_parser('list')
    ann_add = ann_sub.add_parser('add')
    ann_add.add_argument('prefix', help='e.g. [REDACTED:internal-ipv6]/64')
    ann_add.add_argument('kind', choices=ipam.KINDS)
    ann_add.add_argument('--label', default='')
    ann_add.add_argument('--comment', default='')
    ann_add.add_argument('--price', default='')
    ann_add.add_argument('--renewal', default='')
    ann_add.add_argument('--contact', default='')
    ann_del = ann_sub.add_parser('delete')
    ann_del.add_argument('prefix')
    ann.set_defaults(func=cmd_annotations)

    fr = sub.add_parser('free')
    fr.add_argument('--bits', type=int, default=64)
    fr.set_defaults(func=cmd_free)

    zn = sub.add_parser('zone')
    zn_sub = zn.add_subparsers(dest='op', required=True)
    zn_sub.add_parser('render')
    zn.set_defaults(func=cmd_zone)

    st = sub.add_parser('status')
    st.set_defaults(func=cmd_status)

    args = ap.parse_args()
    ipam._init_db()
    args.func(args)


if __name__ == '__main__':
    main()
