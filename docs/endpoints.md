# Endpoint reference

## Public browser routes

- `GET /` serves the neutral Porta landing page.
- `POST /access` exchanges an administrator or active client token for a
  short-lived, role-scoped browser session.
- `/portal/admin` and public `/api/*` require an administrator session.
- `/portal/downloads` and `/download/*` require an administrator or active
  client session.

## Tunnel and proxy routes

- `CONNECT /.well-known/masque/ip/*/*/` is the RFC 9484 unrestricted IPv4
  MASQUE endpoint. It requires Extended CONNECT with `:protocol=connect-ip`,
  `Capsule-Protocol: ?1`, a bearer token, a stable client ID, and a supported
  Porta protocol version.
- `POST /v1/tunnel` is Android's authenticated four-lane HTTP/2 fallback.
  Requests without valid lane metadata or a supported protocol version are
  rejected.
- Standard HTTP `CONNECT` requests form the authenticated HTTPS forward proxy.
  The Basic-auth username is a device ID and the password is a client token.

A token identifies a client account. `X-Porta-Client-ID` identifies one device
under that account. Porta sends optional `X-Porta-DNS` and `X-Porta-MTU`
response extensions because RFC 9484 does not define DNS or link-MTU
configuration.

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

## Session administration

Authorized administrators can end current sessions without changing tokens:

- `POST /api/clients/{clientID}/disconnect`
- `POST /api/clients/{clientID}/devices/{deviceID}/disconnect`

The response includes `disconnected_sessions` (transport sessions, so Android
fallback lanes are counted separately). Disabling or deleting an account,
rotating its token, or forgetting a device also cancels affected active VPN
and forward-proxy sessions. Disconnecting or forgetting alone does not prevent
reconnection with a valid account token.
