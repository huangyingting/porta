# Production deployment

This guide deploys Porta directly on one TCP and UDP port. An existing web
server may continue serving websites and renewing the certificate on port 443,
but native HTTP/3/MASQUE traffic goes directly to Porta and does not pass
through a reverse proxy.

## Choose a deployment mode

| Environment | Command options | Tunnel port | Certificate renewal |
|---|---|---:|---|
| Standalone server | `--domain vpn.example.com` | 443 by default | Porta/Let's Encrypt |
| Another service uses 80/443 | `--domain`, `--cert`, `--key`, `--port 8443` | 8443 | External issuer |
| Custom standalone port | `--domain`, `--port PORT` | Configured value | Porta/Let's Encrypt through TCP 80 |

`--port` controls both the TCP HTTP/2 listener and UDP HTTP/3/QUIC listener.
It defaults to 443. The Android gateway URL must include the port when it is
not 443.

## Prerequisites

- Linux with `curl`, `sha256sum`, `flock` (util-linux), systemd, nftables,
  `/dev/net/tun`, and IPv4 forwarding support
- A DNS hostname pointing to the server
- Either public TCP port 80 for automatic Let's Encrypt issuance, or an
  existing certificate and private key covering the hostname
- Both TCP and UDP on the selected port allowed by host and cloud firewalls

## Download the deployment bundle

Each tagged GitHub release contains a deployment bundle plus standalone server
and client binaries. Download and verify the latest bundle:

```bash
set -o pipefail
gh release download --repo huangyingting/porta \
  --pattern porta-deploy.tar.gz --pattern SHA256SUMS \
  --pattern SHA256SUMS.sig --pattern release-signing-cert.der &&
expected=763e9e1dd32d2f6538149d7b86809af698d1f96c9e29b4e30ec35fc1a8969bd8 &&
actual=$(openssl x509 -inform DER -in release-signing-cert.der \
  -noout -fingerprint -sha256 | tr -d ':' | cut -d= -f2 | tr '[:upper:]' '[:lower:]') &&
test "$actual" = "$expected" &&
openssl x509 -inform DER -in release-signing-cert.der -pubkey -noout > release-public-key.pem &&
openssl dgst -sha256 -verify release-public-key.pem \
  -signature SHA256SUMS.sig SHA256SUMS &&
grep ' porta-deploy.tar.gz$' SHA256SUMS | sha256sum -c - &&
tar -xzf porta-deploy.tar.gz &&
cd porta &&
GH_TOKEN=$(gh auth token) &&
export GH_TOKEN
```

The repository is private, so `gh` must be authenticated with an account that
can read it. Preserve `GH_TOKEN` through `sudo` when using release deployment;
the token is not written to Porta's configuration.

By default, `scripts/deploy.sh` downloads the matching Linux AMD64 or ARM64
`porta-server` from that release, verifies it with `SHA256SUMS`, and requires
a detached signature from Porta's pinned release certificate before executing it.
The signing key is isolated in GitHub Actions and is also the persistent key
whose certificate pins official Android builds. Pass
`--release vX.Y.Z` to pin a release that includes the client download portal.
Developers working from a full source checkout can pass `--build-local`
instead. Local builds require a stable Rust toolchain with Cargo; the deployed
server binary is built from the Rust workspace.

## One-command installation with Let's Encrypt

When no certificate paths are supplied, Porta obtains and renews its own
Let's Encrypt certificate:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --acme-email admin@example.com
```

The email is optional. Let's Encrypt HTTP-01 validation always connects to
public TCP port 80, regardless of the configured tunnel port. DNS must already
point to the server, the cloud and host firewalls must allow TCP 80, and no
other process may own port 80.

This mode is appropriate for a standalone gateway. If another service already
owns port 80, use the existing-certificate mode below instead; stopping a
production web server merely to renew a second certificate is not recommended.

## One-command installation with an existing certificate

From the extracted deployment bundle or a checked-out Porta repository:

```sh
sudo --preserve-env=GH_TOKEN ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --port 8443
```

Certificate and key paths and their resolved targets are validated before
installation. Neither may reside under `/tmp` or `/var/tmp`, because the
hardened synchronization unit uses a private temporary directory. The supplied
live symlink paths are preserved so later synchronization follows certificate
renewal. Private-CA and self-managed certificates are supported: deployment
verifies the key pair before installation, then uses the installed certificate
as explicit trust material to verify TLS and the hostname on the loopback-bound
public listener. These local probes bypass HTTP proxy environment settings.

Porta's authenticated HTTPS CONNECT proxy is enabled on the same TLS port by
default. Add `--disable-forward-proxy` only when the deployment should provide
VPN service without the proxy.

The default deployment:

- listens on TCP and UDP 443;
- uses HTTP/3 MASQUE with HTTP/2 fallback;
- enables authenticated HTTPS CONNECT proxying;
- creates `porta0` and the `10.66.0.0/24` client network;
- advertises `1.1.1.1` and selects HTTP/3 MTU automatically between 1100 and
  the default 1400 ceiling; custom advertised DNS must be a
  numeric unicast IPv4 address, not loopback or link-local;
- installs narrowly scoped nftables NAT, forwarding, and public-input guard
  rules;
- installs hardened systemd services and runs the daemon as the unprivileged
  `porta` system user (see [Service user](#service-user));
- either renews its own Let's Encrypt certificate or synchronizes externally
  managed certificate files every six hours;
- tunes Linux UDP buffers for QUIC;
- creates random fallback and metrics tokens on first installation;
- preserves existing credentials and lease state during upgrades.

Run `sudo ./scripts/deploy.sh --help` for network and port overrides. For
example:

```sh
sudo ./scripts/deploy.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem \
  --port 8443 \
  --external-interface ens3 \
  --pool 10.77.0.0/24 \
  --gateway-cidr 10.77.0.1/24
```

### Service user

`porta-server` runs as the `porta` system user, which deployment creates on
first installation. It holds only the ambient `CAP_NET_ADMIN` capability, plus
`CAP_NET_BIND_SERVICE` for ports below 1024 such as 443 and the ACME HTTP-01
listener on 80. It owns `/var/lib/porta` (the client registry, leases, usage,
ACME cache, and upstream identity) and can read but not change its
configuration:

- `/etc/porta/porta.env` is read by systemd as root and stays `0600`.
- Static certificates are published to `/etc/porta/tls` as `root:porta`, with
  the private key `0640`; `porta-cert-sync.service` keeps this on renewal.
- Custom landing templates in `/etc/porta/landing` are made group-readable
  by `porta` on every deployment.

The `server-up.sh` and `server-down.sh` network helpers run as root through
systemd's `!` prefix, inside the same sandbox and capability bounding set.
They keep their recovery journals in `/run/porta`, which
`/etc/tmpfiles.d/porta.conf` creates root-only, so the daemon cannot read or
alter them. Upgrades from releases that ran the daemon as root hand existing
state to `porta` automatically.

### Automatic tunnel MTU

Conservative per-connection HTTP/3 selection is enabled by default, with a
1400 ceiling and 1100 discovery baseline. `--mtu` sets the gateway TUN MTU
and automatic upper bound. Use `--auto-mtu=false --mtu 1100` to disable
discovery and use a fixed 1100 MTU; another fixed MTU can be specified with
the same override. The daemon accepts the same options when started directly.
The deployment script accepts MTUs from 576 through 1400.

MTU feedback requires Linux to accept gateway-sourced ICMP injected through
TUN, in both automatic and fixed interface-MTU modes. Deployment passes
`--auto-mtu` to the daemon; `server-up.sh` takes five positional arguments plus
the optional `--upstream-interface IF` (cascade relay), repeatable
`--exit-interface IF`, `--local-exit` and `--client-host-access` options. It
always sets `accept_local=1` and loose `rp_filter=2` only on the owned TUN,
and on a relay's upstream and exit TUNs. It does not change global or
physical-interface reverse-path
filtering. These interface-local settings disappear with the TUN. The helper
records the host's previous `net.ipv4.ip_forward` value under `/run/porta` and
restores it during normal cleanup when no administrator or other service has
changed the setting in the meantime.

The network helper invocation is independent of startup discovery:

```sh
sudo ./scripts/server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443
```

Use the actual interface/address/pool values. When selecting fixed mode in a
manually edited service unit, pass `--auto-mtu=false` only to the daemon and
remove the obsolete MTU-mode argument from `server-up.sh`. Upgrade the daemon,
unit and helper together.
The required `mtu_feedback` readiness component detects missing local-source
acceptance or effective strict reverse-path filtering instead of reporting
tunnel forwarding ready with unusable DF feedback.

Clients need no additional setting. They increase above 1100 only after
bidirectional datagram confirmation, agree with the server before configuring
the interface, and keep that MTU until reconnect. Inconclusive discovery keeps
the conservative value; HTTP/2 and capsule-only HTTP/3 retain the configured
MTU. HTTP/3 Datagram sends additionally follow Quinn's current payload capacity
without resizing the live interface. Oversized IPv4 packets use fragmentation
or rate-limited ICMP feedback first; non-adapting DF flows have a bounded,
observable reliable compatibility escape. See
[MTU selection](architecture.md#stable-per-connection-mtu-selection) for
protocol details and oversized IPv4 handling.

### Upgrade behavior

The script serializes deployments with a lock and is idempotent. Re-running it
downloads and upgrades the server while preserving `/etc/porta/porta.env`,
`/var/lib/porta/clients.json`, and persistent leases.

Deployment options are saved in `/etc/porta/deploy.conf`, so an upgrade needs
no options at all: `sudo ./scripts/deploy.sh`. Any option given on a later run
overrides its saved value, is saved in turn, and is reported as
`deploy: changing NAME: OLD -> NEW` before services are stopped. Use the
explicit off-switches to remove saved behavior: `--no-upstream`, `--acme`
(forget a saved certificate path), `--client-to-client=false`,
`--client-host-access=false`, `--routes=`, `--dns-domains=`,
`--trust-proxy-headers=false`, and
`--forward-proxy=true|false`. The external interface is saved only when given
explicitly; otherwise it is detected on every run. An invalid or
hand-edited file with unknown keys or unsafe characters is rejected before
anything is stopped.
The gateway address is derived from the pool unless explicitly supplied. A
pool change is rejected when existing leases are incompatible; use
`--reset-leases` to archive those leases deliberately.

The generated unit carries an inert ordering rule for `docker.service`. If
Docker is installed, deployment also adds it as a weak startup dependency so
Porta starts only after Docker has initialized its firewall chains. Porta then
installs its two forwarding exceptions in `DOCKER-USER`. Without Docker, no
Docker service is started and no iptables rules are added; Porta uses only its
isolated nftables table. If Docker is installed later, restart Porta once after
Docker starts, or rerun deployment, to add the live exceptions; subsequent
boots retain the correct ordering.

## Cascade relays (multi-hop)

A gateway can forward its clients' traffic through another Porta gateway
instead of exiting from its own host, like a multi-hop WireGuard chain.
Chains can be any length; each relay only knows its next hop:

```text
clients -> relay A -> relay B -> exit C -> Internet
```

Deploy from the exit backwards:

1. Deploy the exit gateway normally.
2. On the exit, create a client account for the relay in the admin portal (or
   use its initial `PORTA_TOKEN`). The relay enrolls as one device of that
   account, named after the relay's hostname.
3. Deploy the relay with the exit as its upstream. Provide the token through
   the environment, a private file, or the interactive prompt; it is never a
   command-line value:

   ```sh
   read -rsp "Exit client token: " PORTA_UPSTREAM_TOKEN && echo
   export PORTA_UPSTREAM_TOKEN
   sudo --preserve-env=GH_TOKEN,PORTA_UPSTREAM_TOKEN ./scripts/deploy.sh \
     --domain relay.example.com \
     --upstream https://exit.example.com
   unset PORTA_UPSTREAM_TOKEN
   ```

   Use `--upstream-token-file /root/exit.token` instead of the environment if
   preferred, and `--upstream-ca /path/ca.pem` when the next hop uses a
   private CA. Upgrades reuse the saved token from `/etc/porta/porta.env`.
4. Repeat for each earlier hop, pointing it at the next one.

Clients connect to the first relay exactly as they would to any gateway. Every
hop can keep the default `10.66.0.0/24` pool: the relay masquerades its clients
to a fixed relay address (`--upstream-address`, default `169.254.66.1`) on
`porta-up0` and translates only that address to and from its upstream lease,
so the upstream lease never becomes a local address. Each hop decapsulates and
re-encapsulates rather than nesting tunnels, so the inner MTU is the smallest
hop MTU instead of shrinking at every hop; relays also clamp TCP MSS on the
upstream path.

Relays fail closed. Client traffic is policy-routed (routing table and rule
priority `10066`) only to `porta-up0`, an unreachable fallback route covers
the time the interface is absent, and the forward filter accepts client traffic
only toward the upstream interface. While the next hop is unavailable, relayed
traffic is dropped rather than leaving through the relay's own Internet
connection, and the relay reconnects automatically with exponential backoff.
The relay's own traffic, such as ACME renewal and its tunnel to the next hop,
still uses the host's normal routes.

Relay readiness adds two required components: `upstream_tunnel` reports the
next-hop connection and its last error, and `upstream_route` asks the kernel
how it would forward a client packet. A relay is therefore ready only once the
next hop accepts its token and device. Deployment prints the readiness report
if that does not happen; typical causes are a wrong token, an exhausted device
limit on the next hop's account, or an unreachable next hop. Monitor
`porta_upstream_connected` and `porta_upstream_packets_total` in metrics.

Avoid loops: a chain that eventually points back to an earlier hop forwards
packets until their TTL expires.

## Built-in DNS resolver

`--dns-resolver` (`deploy.sh --dns-resolver`) serves DNS on the gateway's
tunnel address, `10.66.0.1` by default, and advertises it to clients instead
of `--dns`:

- Every connected device gets a name, `device.account.porta.internal`, built
  from its device and account names (duplicates get a short suffix). The
  admin page shows each device's name. A client resolves only the devices it
  may reach (same account, shared access group, or `--client-to-client`, and
  both access policies); other names do not exist for it. Reverse lookups of
  client addresses return these names.
- Other names are forwarded to `--dns-upstream` resolvers
  (`deploy.sh --dns-upstreams 9.9.9.9,149.112.112.112`), by default the
  host's `/etc/resolv.conf` servers. `--dns-forward corp.example=10.20.0.53`
  sends a domain and its subdomains to another resolver, for example an
  internal zone reached through a subnet router.
- `--dns-blocklist FILE` refuses listed domains and their subdomains with
  NXDOMAIN. The file holds one domain per line or uses hosts-file format, and
  is reloaded within a minute of changing. `deploy.sh` installs it as
  `/etc/porta/dns-blocklist.txt`, which you can then edit in place.

Split tunnels add `porta.internal` to their DNS domains automatically. The
resolver answers only live clients and the gateway host: `server-up.sh` drops
traffic to the gateway's tunnel address from any other interface. On a
cascade relay, forwarded queries leave from the relay itself, not through the
exit; point `--dns-upstream` at a resolver you trust there. The daemon needs
`CAP_NET_BIND_SERVICE` for port 53, which `deploy.sh` grants.

## Exit selection

A gateway can offer several exits and let each account choose one in its
access policy, for example to route some customers through another region.
Name each additional next hop with `--exits`, and offer this host's own
egress with `--local-exit` on a relay:

```sh
sudo PORTA_UPSTREAM_TOKEN=... PORTA_EXIT_TOKEN_US=... ./scripts/deploy.sh \
  --upstream https://eu.example.com --exits us=https://us.example.com --local-exit
```

The daemon options are `--exit NAME=URL` (repeatable, at most 8) with the
client token in `PORTA_EXIT_TOKEN_<NAME>` (upper case, `-` as `_`), and
`--local-exit`. All next hops share `--upstream-ca`, `--upstream-transport`
and the gateway's upstream device key, which each next hop enrolls like any
other device. Exit *i* uses the TUN `porta-up<i>` and routing table
`10066+i`; `server-up.sh` takes the matching `--exit-interface` and
`--local-exit` options. Without `--upstream`, traffic exits locally by
default and `local` is selectable next to the named exits.

Pick an account's exit in the admin page's **Network access** section or set
`exit` with `PUT /api/clients/{id}/access`. The gateway installs a policy
routing rule for each of the account's leases before its tunnel carries
traffic, and removes it when the tunnel ends. A selected exit that is down
blackholes that account's traffic instead of falling back to another path;
readiness reports each named exit as an optional `exit_<name>` component,
and the admin page shows every next hop.

## Client isolation

VPN clients can never reach link-local destinations, including the cloud
instance metadata service at `169.254.169.254` (and Alibaba Cloud's
`100.100.100.200`), through the gateway. Metadata services trust requests from
the VM itself, so without this rule any client account could read the gateway
VM's instance credentials. The forward proxy applies the same restriction.

Clients can also reach only two services on the gateway host itself: ICMP,
such as ping, and DNS on port 53, for operators who advertise a resolver on
the gateway with `--dns`. Other host services, such as SSH or databases
listening on all addresses, are unreachable from the tunnel. Add
`--client-host-access` to allow clients to reach every host service, for
example to administer the gateway over the tunnel; metadata remains blocked.

## Client-to-client traffic and access policy

The gateway switches traffic between clients itself; the kernel never
forwards it. Devices of one account always reach each other. Devices of
different accounts reach each other only when both accounts share an access
group, or when the daemon runs with `--client-to-client`
(`deploy.sh --client-to-client`), which makes every client a peer, as in a
hub-and-spoke WireGuard bounce server. Enable that only when all clients are
trusted to see each other.

Each account also has an access policy, set in the admin page's **Network
access** section or with `PUT /api/clients/{id}/access`:

- **Allowed destinations**: IPv4 prefixes the account may reach. Empty allows
  everything.
- **Blocked destinations**: prefixes the account may never reach; they win
  over allowed ones and over a shared group.
- **Group**: accounts with the same group name reach each other's devices and
  subnets.

The gateway address and its `--dns` server stay reachable whatever the lists
say. Policies apply to traffic in both directions between clients, and to
traffic toward the exit. Changing an account's policy reconnects its devices,
which pick up the new rules automatically.

## Subnet routing (site-to-site)

A device can publish the network behind it, like a WireGuard peer with
`AllowedIPs` or a Tailscale subnet router. In the admin page, open the
account's devices and choose **Subnets** for the router device, or call
`PUT /api/clients/{id}/devices/{device}/subnets` with
`{"subnets": ["10.30.0.0/24"]}`. Subnets must be unicast prefixes of `/8` or
longer, may not overlap the client pool or another device's subnets, and are
limited to 16 per device.

Run the Linux client on that device with `--subnet-router`. It enables IPv4
forwarding (restoring the previous value when it disconnects) and
masquerades tunnel traffic toward the subnets, so LAN hosts need no route back
to the client pool. The gateway then accepts packets from that device whose
source lies in its subnets, routes the subnets to it, and lets peers reach
them under the same rules as client-to-client traffic: same account, shared
group, or `--client-to-client`, and each side's access policy. Hosts behind a
subnet router can only talk to clients, never to the exit. Split-tunnel
clients also route every published subnet and the client pool through the
tunnel. A host firewall that drops forwarded traffic on the router, such as
Docker's `FORWARD` policy, must allow traffic from the tunnel interface to the
LAN.

## Split tunneling

By default clients send all IPv4 traffic through the gateway (a full tunnel).
To tunnel only private networks behind the gateway, advertise them with
`--routes` and, optionally, the DNS domains the gateway's resolver should
answer:

```sh
sudo ./scripts/deploy.sh --routes 10.20.0.0/16,192.168.5.0/24 \
  --dns 10.20.0.53 --dns-domains corp.example
```

The daemon options are `--route CIDR` and `--dns-domain NAME`, repeated per
entry (at most 64 routes and 16 domains). Routes cannot be `/0`, loopback, or
multicast; DNS domains require routes. `--routes=` restores a full tunnel.

Clients then route only those prefixes and the `--dns` resolver into the
tunnel; all other traffic keeps the device's own network. Leak protection is
scoped the same way: advertised prefixes are blocked outside the tunnel while
it reconnects, and everything else is unaffected. DNS behaves per platform:

- Linux scopes the tunnel resolver to the domains with a systemd-resolved
  routing domain; without domains the host resolver is untouched.
- Windows adds NRPT rules for the domains; without domains it sets no tunnel
  DNS.
- Android cannot scope DNS by domain for a VPN, so with domains it sends all
  DNS to the tunnel resolver, and without domains it leaves DNS alone.

The admin page shows a **Split tunnel** banner listing the advertised routes,
and every client shows whether its connection is a full or split tunnel.

## Token portal and client downloads

Release clients are mirrored from the private GitHub release to the deployed
Porta server:

```text
porta-client-linux-amd64
porta-client-linux-arm64
porta-client-windows-amd64.zip
porta-android-arm64-v8a.apk
porta-android-armeabi-v7a.apk
porta-android-x86_64.apk
```

The neutral landing page accepts either an administrator token or a client
token. Client tokens open the protected downloads page. For scripted downloads,
create a session cookie before requesting a fixed artifact path:

```sh
curl -fsS -c porta.cookies \
  --data-urlencode "token=$PORTA_TOKEN" \
  https://vpn.example.com:8443/access >/dev/null
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/porta-android-arm64-v8a.apk
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/SHA256SUMS
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/SHA256SUMS.sig
curl -fsSLO -b porta.cookies \
  https://vpn.example.com:8443/download/release-signing-cert.der
expected=763e9e1dd32d2f6538149d7b86809af698d1f96c9e29b4e30ec35fc1a8969bd8
actual=$(openssl x509 -inform DER -in release-signing-cert.der \
  -noout -fingerprint -sha256 | tr -d ':' | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
test "$actual" = "$expected"
openssl x509 -inform DER -in release-signing-cert.der -pubkey -noout \
  > release-public-key.pem
openssl dgst -sha256 -verify release-public-key.pem \
  -signature SHA256SUMS.sig SHA256SUMS
grep ' porta-android-arm64-v8a.apk$' SHA256SUMS | sha256sum -c -
```

Only the listed release filenames are served. There is no directory listing,
and unauthenticated requests retain the neutral landing behavior.
Authenticated GitHub release downloads remain available as an operator
fallback.

The public listener serves a restrictive `/robots.txt` and sends
`X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex` on
landing and HTML portal responses. These directives discourage compliant
search engines and archival crawlers, but they are not access control and
cannot prevent a scraper that chooses to ignore them. Tunnel and forward-proxy
handshakes are unchanged.

## Forward proxy

The forward proxy uses the same client accounts managed by the admin UI. The
Basic-auth username is ignored and the password is the client token:

```sh
curl --proxy https://vpn.example.com:8443 \
  --proxy-basic --proxy-user 'laptop:CLIENT_TOKEN' \
  https://example.com/
```

Porta supports HTTPS `CONNECT` over HTTP/1.1 and HTTP/2. HTTP/3 is reserved for
the native MASQUE CONNECT-IP tunnel and rejects ordinary forward-proxy
CONNECT requests. Ordinary HTTP proxy requests are rejected, and only public
destinations on port 443 are permitted.
DNS results are checked before dialing, and any private, loopback, link-local,
metadata, multicast, documentation, or benchmark address rejects the request.
Only complete, validated public address sets enter the bounded 30-second DNS
cache. IPv4 and IPv6 connection attempts are interleaved with a short stagger
under one setup timeout, so an unreachable preferred family does not serialize
the full connection delay.
Proxy credentials and client-supplied forwarding identity headers are never
sent to the destination.

Valid Basic credentials activate the proxy. Porta returns a standard `407`
challenge only for CONNECT requests so browser extensions can supply stored
credentials. Ordinary unauthenticated requests still fall through to the
landing or unsupported-request behavior.
Configure ZeroOmega with type **HTTPS**, enter the Porta hostname and port, put
any value in its required username field, and use the client token as the
password. ZeroOmega supplies the stored credentials after the CONNECT-only
authentication challenge. All proxy clients for one account are represented by
one `forward-proxy` enrollment and combined usage record; they cannot be managed
individually. Porta
does not serve a public PAC file and does not cache proxy responses. Response
stream writes are flushed after 128 KiB or two milliseconds, whichever comes
first, preserving interactive latency without forcing a protocol flush for
every relay-buffer write.

The installer validates port availability before stopping an existing
gateway. If the new service cannot obtain its certificate or pass the
readiness check, it restores the previous binary, helpers, configuration and
TLS files, downloads, leases, client registry, usage state, sysctl values, and
service enablement/activity. Snapshots are taken after the old gateway and
certificate synchronization have stopped. If a rollback step fails, the script
reports the error and retains its recovery directory rather than deleting the
backups.

## Landing page and role-based portal

Porta randomly selects one of its six bundled, responsive landing templates for
each ordinary browser request. Operators can replace that pool with custom
full-page HTML files by placing one or more regular `.html` files in
`/etc/porta/landing` and restarting the service:

```sh
sudo install -m 0644 my-landing-page.html /etc/porta/landing/
sudo systemctl restart porta
```

Files are loaded in filename order at startup, and one is selected randomly
for each response. An empty directory keeps the bundled templates. Each file
is limited to 1 MiB. The landing response policy permits inline CSS and
same-origin fonts and images, but blocks scripts, external resources, framing,
and form submissions to other origins. Porta also sends `Cache-Control:
no-store` and the crawler directives described above for every template.
Direct runs can use `--landing-template-dir /absolute/path`.

Each bundled page routes its access action to the same role-based portal.
Administrator tokens open the admin console and active client tokens open the
download page. The resulting
role-scoped session expires after eight hours and uses a `Secure`, `HttpOnly`,
`SameSite=Strict` cookie. Tokens are not placed in URLs or browser storage.

```sh
sudo sed -n 's/^PORTA_ADMIN_TOKEN=//p' /etc/porta/porta.env
```

Browse to the public Porta URL and enter that token. The compact
operations table shows live sessions, persisted traffic and connection totals,
transport/address details, recent activity, capacity pressure, and stale or
unused clients. It can create, edit, disable, and delete clients; rotate tokens;
set device limits; and forget enrolled devices to free a slot. Usage is
checkpointed every 30 seconds to `/var/lib/porta/usage.json` by release
deployments. A device that still has the shared
client token can enroll again. Tokens are shown only when created or rotated.

Public admin API calls require the administrator session. Loopback admin API
calls continue to accept `Authorization: Bearer <PORTA_ADMIN_TOKEN>`.
`/healthz`, `/readyz`, and `/metrics` remain loopback-only.

For direct manual server runs, pass `--landing-page=false` to replace the landing
page with normal API 404 responses. Use `--admin-listen` to change or disable
the loopback health, readiness, metrics, and API listener.

## Reverse proxies

The deployment script deliberately does not edit or reload reverse-proxy
configuration. When another service owns port 443, deploy Porta with
`--port 8443`. A reverse proxy may forward HTTP/2 requests to that TLS listener
for the native multi-lane fallback if it supports unbuffered duplex streaming.
Add `--trust-proxy-headers` when the proxy connects from loopback so
authentication limits use each forwarded client address. Porta ignores those
headers from non-loopback peers. The proxy must replace or safely append
`X-Forwarded-For`; it must also preserve independent backend TCP connections
for the logical lanes. Multiplexing them onto one upstream HTTP/2 connection
defeats most of their loss isolation. Porta logs this condition and increments
`porta_http2_collapsed_lane_groups_total`. Configure an HTTP/1.1 upstream or
connect clients directly when the metric increases. Native MASQUE clients
should use `https://vpn.example.com:8443` directly so UDP traffic reaches Porta.

## Firewall

Allow both protocols on the selected direct port:

```text
TCP 443 (or configured port): HTTP/2 over TLS
UDP 443 (or configured port): HTTP/3/QUIC MASQUE
```

Deployment installs a separate `inet porta_guard` nftables table with an
accept-policy input chain at priority `-10`. It matches only the configured
external interface and Porta port; it does not change the host-wide firewall
policy or rules for Caddy, SSH, or other services. Per-source IPv4 and IPv6
meters drop only excessive new traffic:

- TCP initial SYNs: 200 per second with a 400-packet burst;
- UDP new-flow packets: 500 per second with a 1000-packet burst.

Each per-source tracking set is capped at 65,535 source entries with a ten-second source
timeout. Established traffic, unrelated ports, and ICMP/ICMPv6 PMTU feedback
do not match these drop rules. Forwarding/NAT and input-guard tables are
replaced in one nftables transaction and removed together when the service
stops.

The deployment script does not modify UFW, firewalld, Azure NSGs, AWS security
groups, or other cloud perimeter policy. Open the selected TCP and UDP port in
every applicable layer.

For Azure, keep the NSG as the first VM-independent filter:

- allow the Porta port on both TCP and UDP;
- retain TCP 80/443 and UDP 443 only when another service such as Caddy needs
  them;
- keep the loopback admin port closed externally;
- restrict SSH to known administration source ranges;
- remove broad inbound allow rules that make narrower rules ineffective.

An NSG is an L3/L4 allow/deny gate, not a per-source rate limiter. Use Azure
DDoS IP Protection or Network Protection when the public IP needs managed
volumetric-attack mitigation. The NSG, Azure DDoS service, host nftables
meters, transport admission, and authentication limiter protect different
resource boundaries and should be used together.

## Clients and credentials

The first deployment creates a default client using the generated bootstrap
token:

```sh
sudo sed -n 's/^PORTA_TOKEN=//p' /etc/porta/porta.env
```

Use the admin UI for additional clients. Each client receives one random token
that can enroll multiple unique device IDs up to its configured limit. The
registry stores only token hashes in `/var/lib/porta/clients.json`. Disabling a
client, deleting it, or rotating its token cancels its existing VPN lanes and
forward-proxy connections as well as blocking the old credentials. The action
waits for session workers and accounting to finish. Forgetting a device also
disconnects it, but a device with a still-valid shared token can enroll again.
Use **Disconnect now** to end current sessions without changing credentials;
clients with automatic reconnect enabled may reconnect immediately.

### Device enrollment

A client token can enroll devices, so a leaked token could otherwise add
devices until the account's device limit is reached. Each account has a policy
for device keys it has not seen before, set under **New devices** in the client
dialog or with `PUT /api/clients/{id}/enrollment`:

- **Enroll automatically** (`open`, the default): new devices enroll on first
  connection, up to the device limit.
- **Wait for my approval** (`approval`): a new device is recorded as *awaiting
  approval* and cannot connect. **Approve** it in the device list (it then
  counts toward the device limit) or **Deny** it.
- **Block new devices** (`closed`): new devices are refused.

**Allow new devices for 15 min** opens a temporary window in which new devices
enroll directly whatever the policy, which suits setting up a new phone or
laptop. Already enrolled devices are unaffected by the policy. Denied devices
stay refused until approved or forgotten. At most 16 pending or denied devices
are kept per account; beyond that, new devices are refused. Clients explain
these refusals in their own language. The forward proxy has no device identity
and is not subject to enrollment policy; disable it with
`--disable-forward-proxy` if token-only proxy access is unwanted.

### Account limits

Each client account can have three optional limits, set in the client dialog
of the admin UI or with `PUT /api/clients/{id}/limits`:

- **Expiry:** access ends at the configured time. VPN, forward-proxy and portal
  access are refused afterwards, and live sessions end within a few seconds.
- **Monthly data quota:** uploaded plus downloaded tunnel and proxy traffic per
  UTC calendar month. The first period starts when the quota is set, and each
  new month starts a new period. An exhausted account is disconnected and
  refused until the next month, until the quota is raised or removed, or until
  an administrator uses **Reset quota usage**.
- **Speed limit:** a per-direction throughput limit shared by all of the
  account's devices and transport lanes. Excess packets are dropped, which
  tunneled TCP treats like a slower link.

Limits are enforced every five seconds, so an account can exceed its quota by
roughly five seconds of its traffic. Expired and over-quota clients receive
HTTP 403 with an `X-Porta-Reason` header, and native clients show the reason
instead of a generic authentication error. Packets dropped by speed limits are
counted in `porta_router_dropped_packets_total{reason="rate_limited"}`.

## Validation and operations

For a default port-443 deployment:

```sh
sudo systemctl status porta
sudo journalctl -u porta -f
curl http://127.0.0.1:9090/readyz
sudo ss -lntup | grep ':443'
```

For an existing-web-server deployment, replace 443 with 8443 and include
`:8443` in the URL. Static-certificate deployments also install
`porta-cert-sync.timer`:

```sh
sudo systemctl status porta-cert-sync.timer
curl http://127.0.0.1:9090/readyz
```

The expected listeners are TCP and UDP on the configured port. Certificate
synchronization serializes updates, validates the certificate/key pair, and
restores the previous pair if publication fails. New TLS handshakes load the
renewed certificate without disconnecting active tunnels. During a missing or
incomplete replacement, the server retains its last-good certificate and logs
the reload failure and subsequent recovery.

In automatic Let's Encrypt mode, Porta additionally listens on TCP 80 for
HTTP-01 challenges and stores its ACME account and certificates under
`/var/lib/porta/acme`.

`/readyz` returns a component report, not an unconditional success. Required
checks cover the TUN link and gateway address, pool/default routes, IPv4
forwarding, and the deployed Porta nftables forwarding/NAT and public-input
guard rules. The guard check validates its interface, port, protocol, state,
per-source meters, rates, bounds, and drop verdicts. Missing or failed required
checks return HTTP 503. Deployment passes the expected egress interface; manual
runs can set `--egress-interface`. A routed deployment without NAT can use
`--readiness-require-nat=false`. Reverse-proxy backend mode does not require the
public-input guard because its listener must be loopback-only. On a cascade
relay, the forwarding/NAT checks expect the upstream interface, and the
`upstream_tunnel` and `upstream_route` components are also required. When
deployment's readiness wait fails, it prints this report.

Checks share the `--readiness-timeout` budget (default three seconds). Optional
`--readiness-egress-url` and `--readiness-dns-name` probes report outbound HTTP
and resolution through the configured DNS server; their failures are visible
but do not change local readiness. These host-originated probes do not prove
end-to-end client forwarding or validate cloud firewall policy. Arbitrary
third-party firewall rules are not interpreted by the Porta rule checker.

Metrics include `porta_router_dropped_packets_total{reason="..."}` for queue
overflow, closed/missing sessions and invalid TUN packets, plus
`porta_datagram_oversize_total` for datagrams carried by capsule fallback. The
latter is not a dropped-packet counter. HTTP/2 queue diagnostics include
`porta_router_queue_bytes{lane="..."}`,
`porta_router_queue_bytes_high_water{lane="..."}`, and drop reasons
`queue_tail`, `queue_oldest`, and `queue_expired`. A sustained queue or frequent
TCP tail drops indicates that an outer TCP lane cannot drain at the offered
rate; increasing queue limits would add latency rather than fix congestion.
Public admission metrics are
`porta_public_connections{transport="tcp|quic"}`,
`porta_public_connections_total{transport="tcp|quic"}`,
`porta_public_connection_rejections_total{transport="...",reason="..."}`, and
`porta_quic_retries_total`. Authentication pressure is reported by
`porta_abuse_rejections_total{surface="native|proxy|portal|invitation"}`.
Source addresses are never metric labels.

Authenticated HTTP/3 tunnels emit an INFO transport-start event and final
transport summary, correlated with connection/disconnection events by the
process-local `tunnel_id` (in the `http3_tunnel` span for transport events).
Unexpected failures also emit a WARN with a bounded reason and, where available,
a numeric error code, without logging peer-supplied close text. Normal EOF,
cancellation, and graceful peer closes remain INFO.

The summary records the selected interface MTU, current QUIC and IP datagram capacities,
RTT, path loss/congestion/black-hole counters, and per-tunnel datagram/capsule
counts. QUIC path counters are connection snapshots, not tunnel-only deltas;
compare the start and end records. `datagram_queued_*` counts successful enqueue
operations, which may later be evicted. `capsule_submitted_*` counts IP data
submitted to reliable writes, including writes that later fail or are cancelled.
The disconnect record's `downlink_accounted_*` fields and
`porta_packets_to_client_total` likewise do not confirm delivery.

Oversized fallback logs only its first occurrence per tunnel and accumulates
the total, largest packet, and smallest observed IP datagram capacity in the
summary. A switch to capsule-only operation is logged once. These records help
distinguish QUIC failures from frequent reliable-capsule fallback without
per-packet logs or global DEBUG logging. Fallback counters alone do not prove a
path-MTU black hole or explain every stall.

`porta_datagram_mtu_reductions_total` counts live reductions of the effective
HTTP/3 IP packet budget, not interface changes or dropped packets.
`porta_datagram_oversize_total` continues to count oversized IP packets accepted
for capsule compatibility, rather than all fragmentation/ICMP outcomes.
Compatibility after non-converging DF feedback is reported explicitly and can
still incur reliable-stream head-of-line blocking. It never permits an IP
packet larger than the negotiated client interface MTU.

The server reliable writer has separate queues for eight control commands and
32 data commands, with 64 KiB and 256 KiB byte budgets respectively. The byte
budgets include in-flight writes. A two-second deadline includes queue residence
and stream writing; exhausted queues and deadlines end the tunnel with explicit
`capsule_writer_overloaded` or `capsule_writer_timeout` reasons. Native-client
writes use the shorter of their configured timeout and ten seconds. These
bounds preserve receive/cancellation progress rather than guaranteeing delivery
when a peer stops granting stream credit.

## Android

Install the APK, tap **Add profile**, and enter the direct endpoint:

- Default port 443: `https://vpn.example.com`
- Alternate port: `https://vpn.example.com:8443`

Give the profile a recognizable name and enter the token, then save it and
enable its connection switch. Android generates the immutable device identity
in Android Keystore and reports the device name, with a model-name fallback,
as readable metadata.
The app can store multiple VPN
server profiles with Android Keystore-encrypted tokens, while allowing only one
active connection. The status should show **HTTP/3 MASQUE**. If UDP is blocked,
the app starts an encrypted HTTP/2 control lane and one data lane on the same
configured port, then activates up to two more independent data lanes when
queue pressure, blocked writes, startup delay, or lane failures justify them.
Flows remain pinned to the least-loaded healthy data lane; an individual lane
can reconnect without restarting its healthy siblings.

For the public test deployment:

```text
Portal:  https://porta-dev.i-csu.org:8443
Gateway: https://porta-dev.i-csu.org:8443
```

The default APK is the optimized ARM64 build used by most current phones. Use
`porta-android-armeabi-v7a.apk` for older 32-bit ARM devices or
`porta-android-x86_64.apk` for an emulator. Each APK contains only its
required native Rust library instead of bundling every Android CPU architecture.

## Removal

Stop and disable the units before removing installed files:

```sh
sudo systemctl disable --now porta.service
sudo systemctl disable --now porta-cert-sync.timer 2>/dev/null || true
sudo /usr/local/libexec/porta/server-down.sh porta0 eth0
```

The cleanup helper fails explicitly if required networking tools are missing,
removes tracked Docker exceptions, and restores the saved host IPv4 forwarding
state instead of leaving the machine configured as a router. Failed network
inventory is not treated as successful cleanup. Docker recovery markers are
retained on errors and retired only after the rules, or their chain, are
confirmed absent.

Credential and lease files are intentionally not removed automatically.
