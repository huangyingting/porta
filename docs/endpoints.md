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

## Loopback operations routes

The operations listener defaults to `127.0.0.1:9090`:

- `GET /healthz` reports process health.
- `GET /readyz` reports gateway readiness.
- `GET /metrics` is available only when `PORTA_METRICS_TOKEN` is configured and
  requires that bearer token.
- `/api/*` accepts `PORTA_ADMIN_TOKEN` as a bearer token for local automation.

Keep this listener private. Public browser sessions are handled separately on
the main Porta listener.
