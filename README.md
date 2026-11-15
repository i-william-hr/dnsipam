# dnsipam — dns.inbox.li

Reverse-DNS and IPAM for the delegated prefix **[REDACTED:internal-ipv6]/48**, which
the ISP points at `ns3.inbox.li` and `ns4.william.hr` — both NS names resolve
to this box's external addresses (one host, two NS names, as a delegation
needs two).

Three moving parts:

| piece | where | runs as |
|---|---|---|
| authoritative DNS (BIND 9, named.service) | `/etc/bind/named.conf.{options,local}` | `bind` |
| this web app, `127.0.0.1:[REDACTED:loopback-port]` (dnsipam.service) | `app.py` + `index.html` | `dnsipam` |
| the vhost (ACL + SSO + wildcard cert) | `[REDACTED:server-path]` | — |

The UI lives at **https://dns.inbox.li/** — VPN-only v4 (`[REDACTED:internal-ipv4]/24`) and
VPN-only v6 (`[REDACTED:internal-ipv6]/48`), SSO cookie gate, `*.inbox.li` wildcard
cert. Per the box's credo: a 10.x-v4 service never gets a public IPv6 path.

## What it does

- **PTR records** for the reverse zone `8.c.4.1.0.e.4.9.3.0.a.2.ip6.arpa`.
  The sqlite DB (`data/ipam.db`) is the source of truth; every change
  re-renders `named/db.<zone>`, validates it with `named-checkzone` and
  reloads the zone over rndc. **The zone file is generated output** —
  `/etc/bind/named.conf.local` points at it, and hand edits to it are lost on
  the next record change.
- **IPAM annotations**: mark any aligned block (/48…/128) as `used`,
  `rented` or `reserved`, with label, comment, price, renewal date and
  contact — the rental register. Existing WireGuard assignments (clients
  ::1–::6, the NL `4::/64` and IE `5::/64` routed subnets) are pre-seeded.
- **Free-space finder**: pick a size, get aligned blocks carrying no
  annotation, mark one rented from the result.

## Conventions

- No venv — stdlib only (same model as zfs.inbox.li). `requirements.txt`
  does not exist and should not.
- The app has no login: nginx's SSO gate is the only door, and the loopback
  binding is the backstop. It is also why the unit carries **no
  SystemCallFilter** — the app shells out to `named-checkzone`/`rndc`, and a
  filtered syscall set makes subprocess hang instead of fail.
- `dnsipam` is in the `bind` group: it can read `/etc/bind/rndc.key` (rndc
  reload) and the `named/` directory is group-readable by named. AppArmor
  got a read rule for the zone path in `/etc/apparmor.d/local/usr.sbin.named`.
- `dns_guard` nftables still blocks outside port-53 traffic to every
  dnsmasq-held address; only the two external addresses are exempted, because
  that is where the delegation glue points.

## CLI

```sh
sudo -u dnsipam python3 [REDACTED:server-path] records list
sudo -u dnsipam python3 [REDACTED:server-path] annotations add \
    [REDACTED:internal-ipv6]/64 rented --label "example" --price "€5/mo" --renewal 2027-01-01
sudo -u dnsipam python3 [REDACTED:server-path] free --bits 64
sudo -u dnsipam python3 [REDACTED:server-path] zone render   # re-render + reload
```

## Gotchas

- **rndc failure ≠ lost data.** If a reload fails (named down, key issue) the
  DB change is already committed; the UI surfaces the error and the event log
  records it. Fix named, then use the reload button / `cli.py zone render`.
- **dnsmasq owns the internal :53 addresses** (127.0.0.1, [REDACTED:internal-ipv4], ::1,
  [REDACTED:internal-ipv6]). named binds ONLY the two external addresses — see
  `named.conf.options`. Do not "fix" a bind failure by widening
  `listen-on`; you will collide with dnsmasq.
- The ISP delegation only starts answering once `ns3.inbox.li` /
  `ns4.william.hr` resolve publicly (Gigahost records) **and** the ISP has
  been given those names.
