# Testing DHCP locally

DHCP uses the privileged UDP ports 67/68 and broadcast, so a local test needs
`sudo`. The lease engine, codecs, reply builders, and API are covered by unit
tests; this verifies the full on-the-wire exchange.

## 1. Enable DHCP in the config

```toml
# nomina.toml
[dhcp]
v4_listen = ["0.0.0.0:67"]
# v6_listen = ["[::]:547"]
```

## 2. Run the server (as root, for port 67)

```sh
cargo build --release
sudo ./target/release/nomina --config nomina.toml --web-listen 127.0.0.1:8053
```

Open `http://127.0.0.1:8053`, create the admin account.

## 3. Create a scope

Either on the **DHCP** page in the web UI, or via the API. Example with PXE
options (run after logging in; substitute your session cookie/CSRF, or just use
the UI):

```sh
curl -sS -b cookies -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -X POST http://127.0.0.1:8053/api/dhcp/scopes -d '{
    "name": "lan", "family": "v4",
    "subnet": "192.168.50.0/24",
    "range_start": "192.168.50.100", "range_end": "192.168.50.150",
    "lease_secs": 3600, "server_id": "192.168.50.1",
    "dns_register": true, "dns_zone": "home.lan",
    "options": [
      {"code": 3, "kind": "ip_list", "value": "192.168.50.1"},
      {"code": 6, "kind": "ip_list", "value": "192.168.50.1"},
      {"code": 66, "kind": "text", "value": "192.168.50.2"},
      {"code": 67, "kind": "text", "value": "pxelinux.0"},
      {"code": 60, "kind": "text", "value": "PXEClient"}
    ]
  }'
```

(The pool need not match a real interface for a loopback test — the server hands
out addresses from whatever range you configure.)

## 4. Probe it

```sh
sudo python3 scripts/dhcp_probe.py 127.0.0.1
```

You should see an OFFER then an ACK with the assigned address, lease time,
subnet mask, router/DNS, and — because options 66/67 are set — the next-server
(`siaddr`) and bootfile (`file`) PXE fields. The lease then appears on the
**DHCP** page's leases table, and (with `dns_register`) an A record shows up in
the configured zone.

If the probe reports no OFFER on a single host (macOS can drop the broadcast
reply on loopback), run it from another device on the same L2 segment, or point
a real client (set to DHCP) at the server.

## Real clients

Point any DHCP client (a VM, a phone, a spare laptop set to DHCP, or a PXE-booting
machine) on the same segment at the host. Static reservations are matched by MAC
(IPv4) or DUID (IPv6); leases and PXE boot work as configured.
