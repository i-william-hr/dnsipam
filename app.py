#!/usr/bin/env python3
"""
dnsipam — the web/API server behind dns.inbox.li.

Runs on 127.0.0.1:[REDACTED:loopback-port]. nginx is the only intended client: the vhost applies
the source ACL (WireGuard v4 + VPN v6, never public IPv6) and the central SSO
cookie gate before anything reaches here, so this process has no login of its
own — the same model as the other gated apps on this box. Loopback-only
binding is the second half of that arrangement, not a redundancy: nothing
off-box can reach this port even if a vhost is misconfigured.

JSON API under /api/*, the single-page UI from index.html. stdlib only.
"""

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ipam

LISTEN = ('127.0.0.1', [REDACTED:loopback-port])
HERE = os.path.dirname(os.path.abspath(__file__))

MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = 'dnsipam/1.0'

    # --- plumbing ----------------------------------------------------------

    def log_message(self, fmt, *args):
        # One line to stdout; the unit captures it into the journal.
        print('%s %s' % (self.address_string(), fmt % args), flush=True)

    def _send(self, status, body, ctype='application/json; charset=utf-8',
              cache='no-store'):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        self._send(status, {'ok': False, 'error': message})

    def _body(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length > MAX_BODY:
            raise ValueError('request body too large')
        raw = self.rfile.read(length) if length else b'{}'
        data = json.loads(raw.decode('utf-8') or '{}')
        if not isinstance(data, dict):
            raise ValueError('JSON object expected')
        return data

    # --- routing -----------------------------------------------------------

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        query = {}
        if '?' in self.path:
            for kv in self.path.split('?', 1)[1].split('&'):
                if '=' in kv:
                    k, _, v = kv.partition('=')
                    query[k] = v
        try:
            if path == '/' or path == '/index.html':
                with open(os.path.join(HERE, 'index.html'), 'rb') as fh:
                    self._send(200, fh.read(), 'text/html; charset=utf-8')
            elif path == '/favicon.ico':
                with open(os.path.join(HERE, 'favicon.ico'), 'rb') as fh:
                    self._send(200, fh.read(), 'image/x-icon',
                               'public, max-age=604800')
            elif path == '/api/overview':
                self._send(200, {'ok': True, **ipam.overview()})
            elif path == '/api/tree':
                self._send(200, {'ok': True, 'children': ipam.tree_children(
                    query.get('prefix', ipam.PREFIX_STR.split('/')[0]),
                    int(query.get('bits', 48)))})
            elif path == '/api/node':
                self._send(200, {'ok': True, **ipam.node_detail(
                    query.get('prefix', ipam.PREFIX_STR.split('/')[0]),
                    int(query.get('bits', 48)))})
            elif path == '/api/records':
                self._send(200, {'ok': True, 'records': ipam.records_list()})
            elif path == '/api/annotations':
                self._send(200, {'ok': True,
                                 'annotations': ipam.annotations_list()})
            elif path == '/api/free':
                self._send(200, {'ok': True, **ipam.free_blocks(
                    int(query.get('bits', 64)))})
            elif path == '/api/events':
                self._send(200, {'ok': True,
                                 'events': ipam.events_list(100)})
            elif path == '/api/status':
                self._send(200, {'ok': True, 'bind': ipam.bind_zone_status()})
            else:
                self._error(404, 'no such endpoint')
        except (ValueError, KeyError) as exc:
            self._error(400, str(exc))
        except Exception as exc:
            traceback.print_exc()
            self._error(500, 'internal error: %s' % exc)

    def do_POST(self):
        self._mutate('POST')

    def do_PUT(self):
        self._mutate('PUT')

    def do_DELETE(self):
        self._mutate('DELETE')

    def _mutate(self, method):
        path = self.path.split('?', 1)[0]
        try:
            data = self._body()
        except (ValueError, json.JSONDecodeError) as exc:
            return self._error(400, str(exc))

        parts = [p for p in path.split('/') if p]  # ['api', kind, id?]

        def need_id():
            if len(parts) < 3 or not parts[2].isdigit():
                raise ValueError('missing numeric id in %s' % path)
            return int(parts[2])

        try:
            if method == 'POST' and path == '/api/records':
                address = ipam.record_add(
                    data.get('address'), data.get('ptr'),
                    data.get('ttl'), data.get('comment'))
                return self._send(200, {'ok': True, 'address': address,
                                        'message': 'PTR committed and zone reloaded'})
            if method == 'PUT' and len(parts) >= 3 and parts[1] == 'records':
                ipam.record_update(need_id(), data.get('ptr'),
                                   data.get('ttl'), data.get('comment'))
                return self._send(200, {'ok': True,
                                        'message': 'record updated, zone reloaded'})
            if method == 'DELETE' and len(parts) >= 3 and parts[1] == 'records':
                ipam.record_delete(need_id())
                return self._send(200, {'ok': True,
                                        'message': 'record deleted, zone reloaded'})
            if method == 'POST' and path == '/api/annotations':
                ann_id = ipam.annotation_add(
                    data.get('prefix'), data.get('bits'), data.get('kind'),
                    data.get('label'), data.get('comment'),
                    data.get('price'), data.get('renewal'), data.get('contact'))
                return self._send(200, {'ok': True, 'id': ann_id,
                                        'message': 'annotation saved'})
            if method == 'PUT' and len(parts) >= 3 and parts[1] == 'annotations':
                ipam.annotation_update(need_id(), **{
                    k: v for k, v in data.items()
                    if k in ('kind', 'label', 'comment', 'price',
                             'renewal', 'contact')})
                return self._send(200, {'ok': True,
                                        'message': 'annotation updated'})
            if method == 'DELETE' and len(parts) >= 3 and parts[1] == 'annotations':
                ipam.annotation_delete(need_id())
                return self._send(200, {'ok': True,
                                        'message': 'annotation deleted'})
            if method == 'POST' and path == '/api/reload':
                ok, msg = ipam.write_zone_and_reload()
                return self._send(200 if ok else 500, {'ok': ok, 'message': msg})
            self._error(404, 'no such endpoint')
        except ValueError as exc:
            self._error(400, str(exc))
        except RuntimeError as exc:
            # zone render/reload failed after the DB change; the event log
            # carries it and POST /api/reload retries.
            self._error(502, str(exc))
        except Exception as exc:
            traceback.print_exc()
            self._error(500, 'internal error: %s' % exc)


def main():
    ipam._init_db()
    srv = ThreadingHTTPServer(LISTEN, Handler)
    print('dnsipam listening on %s:%d (loopback only)' % LISTEN, flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main()
