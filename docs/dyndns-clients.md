# Configuring DynDNS clients

Nomina exposes a [DynDNS2](https://help.dyn.com/remote-access-api/)-compatible
update endpoint, so most routers and update clients work with it directly.

## 1. Create a token

In the web UI go to **DynDNS → New token**. Give it a label, a **username**, and
the **hostname(s)** it is allowed to update (e.g. `home.example.com`). A
**secret** is generated and shown **once** — copy it.

A token may only update the hostnames assigned to it, and the hostname must fall
inside a zone Nomina is authoritative for.

## 2. The endpoint

```
https://<nomina-host>/nic/update?hostname=<host>&myip=<ipv4>&myipv6=<ipv6>
```

- **Auth**: HTTP Basic with the token `username` : `secret`.
- `hostname` is required (comma-separate several). `myip` / `myipv6` are optional —
  if omitted, the client's **source address** is used (what most routers want).
- Responses are plain text: `good <ip>`, `nochg <ip>`, `nohost`, `badauth`,
  `notfqdn`.
- Serve the management interface over **HTTPS** (or behind a TLS reverse proxy)
  so the credentials aren't sent in clear text. The endpoint is intentionally
  reachable from any source IP (it isn't behind the management allow-list); the
  token is the security boundary.

Replace `<nomina-host>` below with your server (e.g. `dns.example.com:8053`), and
use your token username/secret and hostname.

## FRITZ!Box

**Internet → Permit Access → DynDNS** tab. Set **DynDNS provider** to
*User-defined* (Benutzerdefiniert) and fill in:

| Field | Value |
|-------|-------|
| Update-URL | `https://<nomina-host>/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>` |
| Domain name | `home.example.com` |
| Username | your token username |
| Password | your token secret |

The `<domain>`, `<ipaddr>`, `<ip6addr>` placeholders are filled in by the
FRITZ!Box; it sends the Username/Password as HTTP Basic auth. Drop the `myipv6`
parameter if you only do IPv4.

## OpenWrt (ddns-scripts / LuCI)

**System → Software**: install `ddns-scripts` and `luci-app-ddns`. Then in
**Services → Dynamic DNS** add a service, or edit `/etc/config/ddns`:

```
config service 'nomina'
    option enabled '1'
    option lookup_host 'home.example.com'
    option use_https '1'
    option update_url 'https://[USERNAME]:[PASSWORD]@<nomina-host>/nic/update?hostname=[DOMAIN]&myip=[IP]'
    option domain 'home.example.com'
    option username 'TOKEN_USERNAME'
    option password 'TOKEN_SECRET'
    option ip_source 'network'
    option ip_network 'wan'
    option interface 'wan'
```

For IPv6 add a second `config service` block with `option use_ipv6 '1'`,
`option ip_network 'wan6'`, and `&myipv6=[IP]` in the URL.

## ddclient

`/etc/ddclient.conf`:

```
protocol=dyndns2
ssl=yes
server=<nomina-host>
login=TOKEN_USERNAME
password='TOKEN_SECRET'
use=web, web=https://<nomina-host>/api/health, web-skip='ignore'   # or use=if, if=eth0
home.example.com
```

ddclient's `dyndns2` protocol calls `/nic/update?hostname=...&myip=...` with HTTP
Basic auth, which is exactly what Nomina expects. (Let Nomina detect the IP by
omitting `myip` — set `use=disabled` is not needed; simplest is `use=if` for the
WAN interface, or drop the address entirely and rely on the source IP.)

## inadyn

`/etc/inadyn.conf`:

```
custom nomina {
    hostname    = "home.example.com"
    username    = "TOKEN_USERNAME"
    password    = "TOKEN_SECRET"
    ddns-server = "<nomina-host>"
    ddns-path   = "/nic/update?hostname=%h&myip=%i"
}
```

## UniFi / EdgeOS / VyOS

Use a **custom** DDNS service with the **dyndns2** protocol:

- Server / hostname: `<nomina-host>`
- Login: token username, Password: token secret
- Hostname: `home.example.com`

EdgeOS/VyOS example:

```
set service dns dynamic interface eth0 service custom-nomina host-name home.example.com
set service dns dynamic interface eth0 service custom-nomina login TOKEN_USERNAME
set service dns dynamic interface eth0 service custom-nomina password TOKEN_SECRET
set service dns dynamic interface eth0 service custom-nomina protocol dyndns2
set service dns dynamic interface eth0 service custom-nomina server <nomina-host>
```

## curl / cron (anything else)

Any client that can make an authenticated HTTPS GET works:

```sh
curl -fsS -u TOKEN_USERNAME:TOKEN_SECRET \
  "https://<nomina-host>/nic/update?hostname=home.example.com"
# -> good 203.0.113.7
```

Run it from cron (e.g. every 5 minutes); Nomina returns `nochg` when the address
is unchanged and only bumps the zone serial when it actually changes.
