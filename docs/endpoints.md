# Endpoint reference

## Public browser routes

- `GET /` serves a randomly selected bundled or operator-provided Porta
  landing template.
- `POST /access` exchanges an administrator or active client token for a
  short-lived, role-scoped browser session.
- `GET /join#invite=...` opens QR onboarding. The fragment is handled only by
  the browser, cleared from its address before redemption, and never sent in
  the initial HTTP request.
- `POST /join/redeem` exchanges the encrypted invitation for a client browser
  session and redirects to `/portal/downloads`, without access-key entry.
- `/portal/admin` and public `/api/*` require an administrator session.
- `/portal/downloads` and `/download/*` require an administrator or active
  client session.

## Tunnel and proxy routes

- `CONNECT /.well-known/masque/ip/*/*/` is the RFC 9484 unrestricted
  MASQUE endpoint. It requires Extended CONNECT with `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, a signed native-device proof, and a
  supported Porta protocol version.
- `POST /v1/tunnel` is the authenticated multi-lane HTTP/2 fallback used by
  native clients. A group declares two through four lanes.
  Every lane carries an independent signed native-device proof; requests
  without valid lane metadata or a supported protocol version are rejected.
- Standard HTTP `CONNECT` requests over HTTP/1.1 or HTTP/2 form the
  authenticated HTTPS forward proxy. HTTP/3 is reserved for native MASQUE
  CONNECT-IP. The Basic-auth username is ignored and the password is a client
  token. All forward-proxy requests for an account use the logical device ID
  `forward-proxy`.

A token identifies a client account. Native requests additionally send:

- `X-Porta-Client-ID`: the `d-...` fingerprint of the P-256 public key;
- `X-Porta-Device-Name`: normalized client-reported OS name;
- `X-Porta-Device-Key`: Base64URL DER SubjectPublicKeyInfo;
- `X-Porta-Device-Time`: Unix timestamp;
- `X-Porta-Device-Nonce`: random 16-byte Base64URL nonce;
- `X-Porta-Device-Signature`: ECDSA signature over the method, path, device
  fields, timestamp, nonce, and a hash of the account token.

The server derives the ID from the public key, verifies the signature and
five-minute clock window, and rejects a nonce reused for the same
account/device while the process remains running. Replay state is bounded to
2048 recent nonces per device; further proofs are rejected until entries
expire. Each connection attempt and each Android HTTP/2 lane uses a fresh
nonce. The nonce cache is intentionally in-memory; a restart forgets it, so TLS
and the short timestamp window remain part of replay protection. Forward-proxy
requests do not use this protocol.

Porta sends optional `X-Porta-Gateway`, `X-Porta-DNS` and `X-Porta-MTU` response
extensions because RFC 9484 does not define that interface configuration.
A split-tunnel gateway also sends `X-Porta-Routes` (comma-separated IPv4 and,
with IPv6, IPv6 prefixes, also advertised as a ROUTE_ADVERTISEMENT capsule on
HTTP/3) and
`X-Porta-DNS-Domains` (comma-separated names). Clients treat a malformed or
oversized value as a permanent error rather than guessing a routing policy. The
authenticated gateway address also identifies the source of client-local ICMP
MTU feedback; it is not inferred from an unrelated public endpoint address.

On a dual-stack gateway, HTTP/3 clients request an IPv6 address alongside the
IPv4 one in their ADDRESS_REQUEST capsule. Every ADDRESS_ASSIGN capsule lists
all of the client's addresses, as RFC 9484 requires: answers carry the request
ID, addresses the client did not request carry ID zero, and a request the
gateway cannot satisfy gets the unspecified address. Full tunnels advertise
`::`–`ffff:…` in addition to the IPv4 range. HTTP/2 lanes receive the IPv6
address as `X-Porta-Address6: ADDRESS/128`. Gateways without IPv6, and devices
whose access policy selects a named exit, get no IPv6 address.

HTTP/3 clients additionally request the optional
`X-Porta-MTU-Discovery: 1` capability. Server-side `--auto-mtu` is enabled by
default. When both peers support Datagrams, a nonce in the response header enables
bounded datagram-only probes and reliable MTU selection before address
assignment. The agreed value is the interface ceiling; live HTTP/3 datagram
packet budgets can decrease without changing this agreement or wire version.
No offer means a fixed interface MTU, not a fixed QUIC payload capacity. See the
[MTU extension](architecture.md#stable-per-connection-mtu-selection) for
message formats, bounds, and transport exclusions.

## Loopback operations routes

The operations listener defaults to `127.0.0.1:9090`:

- `GET /healthz` reports process health.
- `GET /readyz` reports required local forwarding components and optional
  external probes; failed required components return HTTP 503. Cascade relays
  add the required `upstream_tunnel` and `upstream_route` components.
- `GET /metrics` is available only when `PORTA_METRICS_TOKEN` is configured and
  requires that bearer token. It serves Prometheus text:
  - `porta_build_info{version}`;
  - tunnels and connections: `porta_active_tunnels`, `porta_connections_total`,
    `porta_public_connections`, `porta_public_connection_rejections_total`;
  - traffic: `porta_traffic_bytes_total{direction}`, packet counters, and
    `porta_router_dropped_packets_total{reason}`;
  - authentication: `porta_auth_failures_total`, `porta_abuse_rejections_total`;
  - `porta_tls_certificate_expiry_timestamp_seconds` for the certificate being
    served;
  - `porta_dns_answers_total{outcome}` with the built-in resolver;
  - `porta_upstream_*` on cascade relays;
  - `porta_federation_connected`, `porta_federation_last_sync_timestamp_seconds`
    and `porta_federation_clients` on replicas;
  - `porta_direct_path_devices` with `--peer-to-peer`.

  `deploy/prometheus/porta-alerts.yml` holds alerting rules built on them.
- `/api/*` accepts `PORTA_ADMIN_TOKEN` as a bearer token for local automation.

Keep this listener private. Public browser sessions are handled separately on
the main Porta listener.

## Download access invitations

`POST /api/client-access` requires an administrator browser session (with the
existing same-origin checks) or a loopback API administrator bearer token.
Send `{"origin":"https://porta.example.com:8443","token":"CLIENT_TOKEN"}`.
The token must identify an active client. The response contains `url` and a PNG
data URI in `image`, with `Cache-Control: no-store`.
The image encodes the HTTPS access URL, not an Android profile.

Invitations contain an AES-256-GCM encrypted client account ID and token. They
are bound to the normalized HTTPS origin (including non-default ports) and a
purpose-separated key derived from the administrator token. Invitations
survive restarts with the same key and can be shared with multiple intended
devices. Rotation, disabling, or deletion is checked
against the current client registry at redemption; administrator-key changes
also invalidate invitations. Invitations never grant administrator access.

`POST /join/redeem` accepts exactly one form field, `ticket`, with a 4 KiB
body limit and same-origin enforcement. A valid invitation creates a secure,
HttpOnly, SameSite=Strict client session and returns HTTP 303 to
`/portal/downloads`. Failed redemption shows a generic error without echoing
credentials. The initial invitation is carried in the URL fragment, not its
query; the page removes it before posting. Links remain bearer credentials
and must be shared privately. No external QR service is used.

## Android profile QR codes

Only the authenticated **client download page** displays the profile QR,
alongside **Copy setup** and manual server/token controls. The old
`/api/profile/qr` endpoint is removed. Client sessions retain encrypted token
material in bounded server memory; the registry still persists hashes only.
Current account status and token hash are rechecked before rendering setup.
Administrator sessions can download artifacts but never expose administrator
credentials as client configuration.

The QR text format is:

```text
porta://profile?v=1&server=https%3A%2F%2Fporta.example.com%3A8443&token=example-not-a-secret&name=Phone
```

Values use UTF-8 form-percent encoding (`+` represents a space); parameter
order is irrelevant. Version `1`, `server`, and `token` are required; `name`
is optional. Android rejects unknown or duplicate fields, other versions,
malformed encoding, and non-HTTPS server origins. The server cannot contain
credentials, a query, a fragment, or a path other than `/`. Explicit ports
must be between 1 and 65535. Limits are 2048 bytes for the whole QR URI,
512 bytes for the server, 512 printable ASCII characters for the token, and
80 UTF-8 bytes for the name. Leading/trailing whitespace and control
characters are rejected.

This URI is consumed by Porta's in-app scanner or explicit **Paste setup**
action; it is not an HTTP
endpoint or an exported Android deep link. Import always requires reviewing
and saving a new profile, and does not import a device ID or auto-connect/TLS
override settings.

Android reads `Settings.Global.DEVICE_NAME` independently of profile storage,
QR/paste payloads, and Intent extras, falling back to `Build.MODEL`, then
`android` if neither is usable. Windows and Linux use their OS machine name.
Names are normalized to a 1-64-character ASCII format and sent as mutable
metadata. The immutable enrollment ID is derived from the client-generated
public key, so duplicate names coexist and renaming does not consume a slot.

## Account limits

`PUT /api/clients/{clientID}/limits` replaces an account's limits. All three
fields are required, and `null` removes a limit:

```json
{"expires_at": "2027-01-01T00:00:00Z", "monthly_quota_bytes": 107374182400, "rate_limit_kbps": 20000}
```

`expires_at` is RFC 3339. `monthly_quota_bytes` counts uploaded plus
downloaded IP bytes per UTC calendar month and must be positive.
`rate_limit_kbps` applies to each direction and must be at least 64. Client
summaries in `GET /api/clients` include these fields when set, plus
`quota_used_bytes` for the current period and `status`: `active`, `disabled`,
`expired`, or `quota_exceeded`.

`POST /api/clients/{clientID}/usage/reset` starts a new quota period
immediately and restores a blocked account.

Tunnel requests from expired or over-quota accounts receive HTTP 403 with
`X-Porta-Reason: account-expired` or `X-Porta-Reason: quota-exceeded`. The
reason is sent only after the token has been validated.

Successful tunnel responses for limited accounts carry informational headers
that native clients display: `X-Porta-Account-Expires` (Unix seconds),
`X-Porta-Quota-Bytes`, `X-Porta-Quota-Used-Bytes` (a snapshot at connection
time) and `X-Porta-Rate-Limit-Kbps`. Enforcement never depends on them.

## Device enrollment

`PUT /api/clients/{clientID}/enrollment` sets the policy for unknown device
keys: `{"policy": "open" | "approval" | "closed", "open_for_minutes": 15}`.
`open_for_minutes` (1 to 10080) optionally lets new devices enroll directly
until the window elapses. `POST /api/clients/{clientID}/devices/{deviceID}/approve`
and `.../deny` review a device. Client summaries include `enrollment`,
`enrollment_open_until`, and `pending_devices`, and each device has a
`status` of `approved`, `pending`, or `denied`; `device_count` counts approved
devices. Refused native tunnels receive HTTP 403 with `X-Porta-Reason`
`device-pending`, `enrollment-closed`, or `device-denied`.

The same body's optional `"standard_clients": true | false` allows or stops
[standard CONNECT-IP clients](#standard-connect-ip-clients) for the account;
summaries report it as `standard_clients`. Stopping them ends their sessions.

## Standard CONNECT-IP clients

Porta's own clients add a device proof and `X-Porta-Version` to every tunnel
request. A request to the MASQUE endpoint that carries neither is a standard
RFC 9484 request: it is authenticated by the bearer token alone and admitted
only for accounts with `standard_clients` enabled, otherwise refused with
HTTP 403 and `X-Porta-Reason: standard-clients-disabled`. The target may be
`/.well-known/masque/ip/%2A/%2A/`, as RFC 6570 expansion of the RFC 9484
template produces, over HTTP/3 or HTTP/2 Extended CONNECT. The gateway assigns the client's
addresses and advertises its routes right after the response, with request ID
zero, and also answers ADDRESS_REQUEST capsules. Standard clients receive the
account's access policy, limits and DNS server header like native ones, but
no MTU discovery.

All of an account's standard clients share one logical device,
`standard-masque` (**Standard MASQUE clients** in the device list), which
takes one device slot and one lease: a second standard connection replaces
the first. Without a device key they get none of the device guarantees:
enrollment approval, per-device revocation, and proof against replay of a
stolen token do not apply, so the token is their only credential.
`scripts/test-standard-masque.sh` checks the mode against the independent
quic-go/connect-ip-go client in `experiments/masque-interop`.

## Access policy and subnet routes

`PUT /api/clients/{clientID}/access` replaces an account's access policy:
`{"allow": ["10.20.0.0/16", "10.1.2.3 tcp/443"], "deny": ["10.20.9.0/24"], "group": "team", "exit": null}`.
Every field is optional; empty lists and `null` remove a rule. Each list
holds at most 64 rules: a prefix or address, optionally followed by
`tcp`, `udp` (each with an optional `/PORT` or `/FIRST-LAST`) or `icmp`
([rule semantics](deployment.md#client-to-client-traffic-and-access-policy)). Group names have at most 32 letters, digits, `-`
or `_`, and are stored in lower case. The change reconnects the account's
devices. Client summaries include the policy as `access`.

Device summaries include `dns_name`, the device's name under
`porta.internal`, and `GET /api/gateway` reports `dns_resolver` when the
built-in resolver serves those names.

`PUT /api/clients/{clientID}/devices/{deviceID}/subnets` with
`{"subnets": ["10.30.0.0/24"]}` routes networks to a device, and an empty list
stops routing them; the device reconnects. Device summaries include
`subnets`. The gateway tells the device its subnets with the
`X-Porta-Subnets` response header, and adds other devices' subnets and the
client pool to split-tunnel `X-Porta-Routes`.

## Federation

`GET /federation/v1/registry` on a primary's public listener returns its
client registry (accounts, token hashes, devices and policies) as JSON to
`Authorization: Bearer <PORTA_FEDERATION_TOKEN>`; anything else gets `401`
and is rate limited and audited. A replica that does not know a device
answers tunnel requests with `503` and `X-Porta-Reason`, which multi-gateway
clients treat as a signal to try another gateway.

## Gateway status

`GET /api/gateway` returns the server version and, on a cascade relay, the
next hop: `{"version":"0.1.40","upstream":{"url":"https://exit.example.com","interface":"porta-up0","connected":true,"address":"10.66.0.2","transport":"h3"}}`.
While disconnected, `connected` is `false` and `error` holds the last failure.
A split-tunnel gateway adds `routes` and `dns_domains`, a dual-stack gateway
adds `ipv6_pool`, `client_to_client`
reports `--client-to-client`, `peer_to_peer` reports `--peer-to-peer`, `exits` lists the exit names access policies
may select, and `upstreams` lists every next hop, with `name` set for named
exits. `federation` reports `role` (`primary` or `replica`) and, on a
replica, the `primary`, whether it is `connected`, the `last_sync` time,
the mirrored `clients` count and the last `error`. The admin page shows the routing and next hop as
banners.

## Administrators and audit

Admin API requests run as the signed-in administrator, or as an owner with the
break-glass `Authorization: Bearer PORTA_ADMIN_TOKEN`. Viewers may only read;
operators may change clients; owners may also manage administrators. A
request the role does not allow returns HTTP 403.

- `GET /api/me` returns the caller's `kind` (`token`, `admin` or `sso`),
  `name`, `role` and whether `totp` is on. `POST /api/me/totp` starts TOTP
  enrollment and returns `secret`, `uri` and a `qr_code` data URI;
  `PUT /api/me/totp` with `{"code": "123456"}` turns it on.
  `PUT /api/me/password` takes `{"current": ..., "password": ...}`.
- `GET /api/admins` lists administrators; `POST /api/admins` creates one from
  `{"username", "role", "password", "sso_email", "disabled"}`;
  `PUT /api/admins/{id}` changes any of those except the username;
  `DELETE /api/admins/{id}` removes one, and `DELETE /api/admins/{id}/totp`
  turns off its two-factor authentication.
- `GET /api/audit?limit=200` returns up to 1000 recent `events`, newest
  first; `GET /api/audit/export` downloads every retained event as JSON
  lines.

Browser sign-in uses `POST /admin/sign-in` (form fields `username`,
`password`, `code`), and single sign-on `GET /auth/oidc/start` and
`GET /auth/oidc/callback`. With `--sso-user-domains`, `GET /auth/sso/start`
signs a user in to their account through the same callback and redirects to
`/portal/downloads`.

## Session administration

Authorized administrators can end current sessions without changing tokens:

- `POST /api/clients/{clientID}/disconnect`
- `POST /api/clients/{clientID}/devices/{deviceID}/disconnect`

The response includes `disconnected_sessions` (transport sessions, so Android
fallback lanes are counted separately). Disabling or deleting an account,
rotating its token, or forgetting a device also cancels affected active VPN
and forward-proxy sessions. Disconnecting or forgetting alone does not prevent
reconnection with a valid account token.
