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

- `CONNECT /.well-known/masque/ip/*/*/` is the RFC 9484 unrestricted IPv4
  MASQUE endpoint. It requires Extended CONNECT with `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, a signed native-device proof, and a
  supported Porta protocol version.
- `POST /v1/tunnel` is the authenticated multi-lane HTTP/2 fallback used by
  native clients. A group declares two through four lanes.
  Every lane carries an independent signed native-device proof; requests
  without valid lane metadata or a supported protocol version are rejected.
- Standard HTTP `CONNECT` requests form the authenticated HTTPS forward proxy.
  The Basic-auth username is ignored and the password is a client token. All
  forward-proxy requests for an account use the logical device ID
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

Porta sends optional `X-Porta-DNS` and `X-Porta-MTU` response extensions because
RFC 9484 does not define DNS or link-MTU configuration.

HTTP/3 clients additionally request the optional
`X-Porta-MTU-Discovery: 1` capability. Server-side `--auto-mtu` is enabled by
default. When both peers support Datagrams, a nonce in the response header enables
bounded datagram-only probes and reliable MTU selection before address
assignment. No offer means the ordinary fixed MTU. See the
[MTU extension](architecture.md#stable-per-connection-mtu-selection) for
message formats, bounds, and transport exclusions.

## Loopback operations routes

The operations listener defaults to `127.0.0.1:9090`:

- `GET /healthz` reports process health.
- `GET /readyz` reports required local forwarding components and optional
  external probes; failed required components return HTTP 503.
- `GET /metrics` is available only when `PORTA_METRICS_TOKEN` is configured and
  requires that bearer token.
- `/api/*` accepts `PORTA_ADMIN_TOKEN` as a bearer token for local automation.

Keep this listener private. Public browser sessions are handled separately on
the main Porta listener.

## Download access invitations

`POST /api/client-access` requires an administrator browser session (with the
existing same-origin checks) or a loopback API administrator bearer token.
Send `{"origin":"https://porta.example.com:8443","token":"CLIENT_TOKEN"}`.
The token must identify an active client. The response contains `url`, a PNG
data URI in `image`, and an RFC3339 `expires_at`, with `Cache-Control: no-store`.
The image encodes the HTTPS access URL, not an Android profile.

Invitations contain an AES-256-GCM encrypted client account ID, token, and eight-hour
expiry. They are bound to the normalized HTTPS origin (including non-default
ports) and a purpose-separated key derived from the administrator token.
Unexpired invitations survive restarts with the same key and can be shared
with multiple intended devices. Rotation, disabling, or deletion is checked
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

## Session administration

Authorized administrators can end current sessions without changing tokens:

- `POST /api/clients/{clientID}/disconnect`
- `POST /api/clients/{clientID}/devices/{deviceID}/disconnect`

The response includes `disconnected_sessions` (transport sessions, so Android
fallback lanes are counted separately). Disabling or deleting an account,
rotating its token, or forgetting a device also cancels affected active VPN
and forward-proxy sessions. Disconnecting or forgetting alone does not prevent
reconnection with a valid account token.
