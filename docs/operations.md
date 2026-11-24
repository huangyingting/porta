# Operations

This guide covers running a Porta gateway in production: what to monitor,
what to back up, and how to upgrade, roll back and recover. Deployment itself
is in [deployment.md](deployment.md).

## Where the gateway keeps things

| Path | Contents | In backups |
|---|---|---|
| `/etc/porta/porta.env` | Admin, client, metrics and federation tokens | yes |
| `/etc/porta/tls/` | Certificate and key from `--cert`/`--key` | yes |
| `/etc/porta/deploy.conf` | Options `deploy.sh` reuses on upgrades | yes |
| `/etc/porta/landing/` | Landing page templates | yes |
| `/var/lib/porta/clients.json` | Accounts, devices, limits and access policies | yes |
| `/var/lib/porta/leases.json` | Stable tunnel addresses per device | yes |
| `/var/lib/porta/usage.json` | Monthly data usage per account | yes |
| `/var/lib/porta/admins.json` | Named administrators, roles and TOTP secrets | yes |
| `/var/lib/porta/audit.log*` | Administrative changes, sign-ins and connections | yes |
| `/var/lib/porta/acme/` | Let's Encrypt account and certificates | yes |
| `/var/lib/porta/upstream-identity.json` | A relay's device key at its next hop | yes |
| `/var/lib/porta/downloads/` | Client packages served to users | no; `deploy.sh` fetches them |

The gateway replaces each JSON file atomically, so a copy is always one
complete version of that file.

## Monitoring

Set `PORTA_METRICS_TOKEN` in `/etc/porta/porta.env` and scrape
`http://127.0.0.1:9090/metrics` with that bearer token (see
[endpoints.md](endpoints.md#loopback-operations-routes) for the metrics).
Load [`deploy/prometheus/porta-alerts.yml`](../deploy/prometheus/porta-alerts.yml),
which ships in the deploy bundle. `GET /readyz` on the same listener returns
503 with the failing component when the gateway cannot forward traffic; use it
for load-balancer health checks.

What to do when an alert fires:

- **PortaGatewayDown**
  - Check `systemctl status porta` and `journalctl -u porta -n 200`.
  - A failed start names the bad option or file.
  - `curl -s 127.0.0.1:9090/readyz` names the component that is not ready.
- **PortaCertificateExpiresSoon / Imminently**
  - With ACME, check `journalctl -u porta | grep ACME` for order failures.
    Port 80 (or TLS-ALPN on the public port) must be reachable from the
    Internet.
  - With `--cert`, renew the file; the gateway reloads it within a second,
    and `porta-cert-sync.timer` copies renewed certificates from their
    source.
- **PortaUpstreamDisconnected**
  - The relay's next hop is unreachable or refused it. Relayed clients lose
    service; they do not leak.
  - Check the next hop's status, and the relay's token and device approval
    there.
- **PortaFederationStale**
  - The replica cannot reach its primary or is refused.
  - Clients keep working with the last mirrored accounts.
  - Check `GET /api/gateway` for the federation `error`, then the
    `PORTA_FEDERATION_TOKEN` on both sides.
- **PortaAuthenticationFailures**
  - Usually a revoked token still in use, or a scan.
  - The audit log and `journalctl -u porta | grep "authentication"` show
    the sources.
  - Repeat offenders are already throttled (`porta_abuse_rejections_total`).
- **PortaAdmissionRejections**
  - The gateway is at its connection limits, globally or for one source.
  - A sustained rate from many sources means the host needs more capacity;
    from one source, it is being throttled as intended.
- **PortaQueueDrops**
  - Clients send faster than their path or rate limits allow, or the host is
    CPU-bound.
  - Compare CPU use, `porta_router_queue_bytes` and per-account rate limits.
- **PortaDnsUpstreamFailing**
  - The built-in resolver's upstreams time out.
  - Check `--dns-upstreams` reachability from the host.

## Backups

`deploy.sh` installs `porta-backup` and a daily `porta-backup.timer` that
keeps the newest 14 archives in `/var/backups/porta`. It also takes a backup
before every upgrade of an existing gateway.

```sh
sudo porta-backup create             # now
sudo porta-backup list               # newest first
sudo porta-backup verify /var/backups/porta/porta-20261124T030000Z.tar.gz
```

Archives contain every secret the gateway has: tokens, TLS and ACME keys,
administrator TOTP secrets and the relay's device key. They are root-only;
encrypt before copying them off the host, for example with
[age](https://age-encryption.org):

```sh
sudo porta-backup create | xargs sudo cat | age -r age1... > porta-$(date +%F).tar.gz.age
```

Test a restore on a spare host periodically.

### Restore

```sh
sudo porta-backup restore /var/backups/porta/porta-20261124T030000Z.tar.gz
```

The restore:
1. checks the archive's checksums;
2. stops Porta;
3. moves the current state to `/var/lib/porta/restore-replaced-<time>`;
4. puts the archive's configuration and state in place;
5. starts Porta and waits until it is ready.

Undo it by restoring from the `restore-replaced-*` copy.

To move a gateway to a new host:
1. Deploy the same release there with `deploy.sh` (same `--domain`).
2. Restore the archive.
3. Point DNS at the new host.

Clients keep their device approval, and devices keep their addresses.

## Upgrades

```sh
sudo ./scripts/deploy.sh                 # latest release, saved options
sudo ./scripts/deploy.sh --release v0.1.41
```

`deploy.sh` reuses the options in `/etc/porta/deploy.conf`.
- **Restart:** when only the server binary changes, it reloads Porta in
  place. Sockets, tunnels and leases survive, and clients do not reconnect.
  Option or helper changes restart the service; clients reconnect within
  seconds.
- **Automatic rollback:** if any step fails, `deploy.sh` restores the
  previous binary, configuration, state and units, and restarts the old
  version.

### Rolling back a release

An older release reads newer state files but drops settings it does not
know about (such as a newer access-policy field) the next time it saves
them. To go back without losing anything:

```sh
sudo porta-backup list                      # the "pre-upgrade" archive
sudo ./scripts/deploy.sh --release v0.1.40
sudo porta-backup restore /var/backups/porta/porta-<time before the upgrade>.tar.gz
```

Changes made between the upgrade and the rollback are lost; they are still
in the `restore-replaced-*` copy.

## Routine tasks

- **Rotate the admin token:** edit `PORTA_ADMIN_TOKEN` in
  `/etc/porta/porta.env` and run `sudo systemctl restart porta`. Browser
  sessions and download invitations signed with the old token end.
- **Rotate a client token:** use **Rotate** on the account's token in the
  admin page. Its devices reconnect after their users import the new
  profile.
- **Require an app update:** redeploy with `--min-client-version` set to the
  fixed release; older apps tell their users to update.
- **Revoke a device:** use **Forget** or **Deny** on the device. Its live
  tunnel ends at once, and with `--peer-to-peer` its peers drop their
  direct paths to it.
- **Read the audit log:** `sudo tail -f /var/lib/porta/audit.log`. Each line
  is a JSON event, and rotated files are `audit.log.1` and onward.
