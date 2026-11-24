#!/usr/bin/env bash
# End-to-end test of administrator identities: named accounts and roles,
# TOTP, OpenID Connect single sign-on against a fake identity provider, user
# sign-in that provisions accounts for allowed email domains, and the audit
# log. Runs a real gateway in a network namespace.
#
#   browser + identity provider (172.31.0.1) -- gateway (172.31.0.2)
#
# Usage: sudo scripts/test-admin-identity.sh [path-to-porta-server]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
server_binary=$(realpath "${1:-$repository_root/rust/target/debug/porta-server}")
[[ -x $server_binary ]] || { echo "missing executable: $server_binary (build the workspace first)" >&2; exit 2; }
for command in curl ip openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

suffix=$$
work=$(mktemp -d /tmp/porta-identity.XXXXXX)
chmod 0700 "$work"
pids=()
admin_token=admin-token-0123456789abcdef
gateway=https://172.31.0.2:8443
idp=https://172.31.0.1:9443

ns() { printf 'pi%s-%s' "$suffix" "$1"; }
in_ns() { local name=$1; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for node in browser gateway; do
    ip netns delete "$(ns "$node")" 2>/dev/null || true
  done
  if [[ $status -ne 0 ]]; then
    echo "administrator identity test failed; logs:" >&2
    for log in "$work"/*.log; do
      [[ -f $log ]] || continue
      echo "==> $log" >&2
      tail -n 30 "$log" >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for node in browser gateway; do
  ip netns add "$(ns "$node")"
  in_ns "$node" ip link set lo up
done
ip link add east netns "$(ns browser)" type veth peer name west netns "$(ns gateway)"
in_ns browser ip address add 172.31.0.1/30 dev east
in_ns gateway ip address add 172.31.0.2/30 dev west
in_ns browser ip link set dev east up
in_ns gateway ip link set dev west up

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Porta identity test CA" \
  -keyout "$work/ca.key" -out "$work/ca.pem" >/dev/null 2>&1
certificate() {
  local name=$1 address=$2
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$address" \
    -keyout "$work/$name.key" -out "$work/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$work/$name.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf 'subjectAltName=IP:%s\n' "$address") \
    -out "$work/$name.crt" >/dev/null 2>&1
}
certificate gateway 172.31.0.2
certificate idp 172.31.0.1
openssl genrsa -out "$work/signing.key" 2048 >/dev/null 2>&1

# A fake OpenID provider: it signs in whichever email the test names in
# login_hint-style state (email file), and enforces PKCE.
cat >"$work/idp.py" <<'PY'
import base64, hashlib, http.server, json, os, ssl, subprocess, sys, time, urllib.parse

work, issuer = sys.argv[1], sys.argv[2]
def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
modulus = subprocess.check_output(["openssl", "rsa", "-in", f"{work}/signing.key", "-noout", "-modulus"]).decode().split("=", 1)[1].strip()
jwks = {"keys": [{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": b64(bytes.fromhex(modulus)), "e": "AQAB"}]}
codes = {}

def sign(claims):
    header = b64(json.dumps({"alg": "RS256", "kid": "test"}).encode())
    payload = b64(json.dumps(claims).encode())
    message = f"{header}.{payload}".encode()
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", f"{work}/signing.key"], input=message, capture_output=True, check=True).stdout
    return f"{header}.{payload}.{b64(signature)}"

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/.well-known/openid-configuration":
            document = {"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                        "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"}
            return self.reply(200, json.dumps(document).encode(), [("Content-Type", "application/json")])
        if url.path == "/jwks":
            return self.reply(200, json.dumps(jwks).encode(), [("Content-Type", "application/json")])
        if url.path == "/authorize":
            assert query["response_type"] == "code" and query["code_challenge_method"] == "S256"
            code = b64(os.urandom(16))
            email = open(f"{work}/email").read().strip()
            codes[code] = {"nonce": query["nonce"], "challenge": query["code_challenge"],
                           "client_id": query["client_id"], "redirect_uri": query["redirect_uri"], "email": email}
            location = query["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": query["state"]})
            return self.reply(302, b"", [("Location", location)])
        self.reply(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))
        grant = codes.pop(form.get("code", ""), None)
        if self.path != "/token" or grant is None or form.get("redirect_uri") != grant["redirect_uri"]:
            return self.reply(400, b'{"error":"invalid_grant"}')
        if b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != grant["challenge"]:
            return self.reply(400, b'{"error":"invalid_grant","error_description":"PKCE"}')
        now = int(time.time())
        token = sign({"iss": issuer, "sub": "sub-" + grant["email"], "aud": grant["client_id"], "exp": now + 300,
                      "iat": now, "nonce": grant["nonce"], "email": grant["email"], "email_verified": True})
        self.reply(200, json.dumps({"id_token": token, "token_type": "Bearer"}).encode(), [("Content-Type", "application/json")])

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("0.0.0.0", 9443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(f"{work}/idp.crt", f"{work}/idp.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
printf 'carol@example.com\n' >"$work/email"
ip netns exec "$(ns browser)" python3 "$work/idp.py" "$work" "$idp" >"$work/idp.log" 2>&1 &
pids+=($!)

install -d -m 0700 "$work/state"
openssl rand -hex 24 >"$work/token"
ip netns exec "$(ns gateway)" env \
  PORTA_TOKEN="$(<"$work/token")" PORTA_ADMIN_TOKEN="$admin_token" \
  PORTA_OIDC_CLIENT_SECRET=client-secret-0123456789 \
  "$server_binary" --listen ":8443" --admin-listen 127.0.0.1:9090 \
  --tls-cert "$work/gateway.crt" --tls-key "$work/gateway.key" \
  --client-registry "$work/state/clients.json" --lease-state "$work/state/leases.json" \
  --interface porta0 --egress-interface west --pool 10.66.0.0/24 \
  --oidc-issuer "$idp" --oidc-client-id porta-admin --oidc-ca "$work/ca.pem" \
  --oidc-redirect-url "$gateway/auth/oidc/callback" \
  --sso-user-domains example.org --sso-max-devices 3 >>"$work/gateway.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do
  in_ns gateway curl -fsS --max-time 2 http://127.0.0.1:9090/healthz >/dev/null 2>&1 && break
  sleep 0.2
done
for _ in $(seq 1 50); do
  in_ns browser curl -sS --max-time 2 --cacert "$work/ca.pem" "$gateway/admin/sign-in" >/dev/null 2>&1 && break
  sleep 0.2
done

token_api() {
  in_ns gateway curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" "$@"
}
json() { python3 -c "import json, sys; print($1)"; }
token_api -X POST --data '{"username":"alice","role":"owner","password":"correct horse battery"}' \
  http://127.0.0.1:9090/api/admins >/dev/null
token_api -X POST --data '{"username":"bob","role":"viewer","password":"another long password"}' \
  http://127.0.0.1:9090/api/admins >/dev/null
token_api -X POST --data '{"username":"carol","role":"operator","sso_email":"Carol@Example.com"}' \
  http://127.0.0.1:9090/api/admins >/dev/null
echo "the break-glass token created three administrators"

# A browser session: a cookie jar and a same-origin header for form posts.
browser() {
  local jar=$1
  shift
  in_ns browser curl -sS --max-time 10 --cacert "$work/ca.pem" -b "$work/$jar.jar" -c "$work/$jar.jar" "$@"
}
sign_in() {
  local jar=$1 username=$2 password=$3 code=${4:-}
  rm -f "$work/$jar.jar"
  browser "$jar" -o /dev/null -w '%{http_code}' -H "Origin: $gateway" \
    --data-urlencode "username=$username" --data-urlencode "password=$password" \
    --data-urlencode "code=$code" "$gateway/admin/sign-in"
}
api() {
  local jar=$1
  shift
  browser "$jar" -H "Origin: $gateway" -H "Content-Type: application/json" "$@"
}

[[ $(sign_in alice alice "correct horse battery") == 303 ]] || { echo "alice could not sign in" >&2; exit 1; }
[[ $(api alice "$gateway/api/me" | json 'json.load(sys.stdin)["role"]') == owner ]] || {
  echo "alice's session is not an owner" >&2
  exit 1
}
[[ $(sign_in wrong alice "not the password") == 401 ]] || { echo "a wrong password was accepted" >&2; exit 1; }
echo "local administrators sign in with their own passwords"

secret=$(api alice -X POST "$gateway/api/me/totp" | json 'json.load(sys.stdin)["secret"]')
totp() {
  python3 - "$secret" "${1:-0}" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = base64.b32decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 8))
counter = int(time.time()) // 30 + int(sys.argv[2])
digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 15
print("%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000))
PY
}
[[ $(api alice -o /dev/null -w '%{http_code}' -X PUT --data "{\"code\":\"$(totp)\"}" "$gateway/api/me/totp") == 200 ]] || {
  echo "TOTP confirmation failed" >&2
  exit 1
}
[[ $(sign_in alice alice "correct horse battery") == 401 ]] || { echo "TOTP was not required" >&2; exit 1; }
grep -q "Enter the code" <(browser probe -H "Origin: $gateway" --data "username=alice&password=correct+horse+battery&code=" "$gateway/admin/sign-in")
code=$(totp 1)
[[ $(sign_in alice alice "correct horse battery" "$code") == 303 ]] || { echo "a valid TOTP code was refused" >&2; exit 1; }
[[ $(sign_in replay alice "correct horse battery" "$code") == 401 ]] || { echo "a TOTP code was accepted twice" >&2; exit 1; }
echo "two-factor authentication is enforced and codes cannot be replayed"

[[ $(sign_in bob bob "another long password") == 303 ]] || { echo "bob could not sign in" >&2; exit 1; }
[[ $(api bob -o /dev/null -w '%{http_code}' "$gateway/api/clients") == 200 ]] || { echo "a viewer could not read clients" >&2; exit 1; }
[[ $(api bob -o /dev/null -w '%{http_code}' -X POST --data '{"name":"X","max_devices":1}' "$gateway/api/clients") == 403 ]] || {
  echo "a viewer could create a client" >&2
  exit 1
}
[[ $(api bob -o /dev/null -w '%{http_code}' "$gateway/api/admins") == 403 ]] || { echo "a viewer could list administrators" >&2; exit 1; }
echo "roles limit what each administrator can do"

sso_sign_in() {
  local jar=$1
  rm -f "$work/$jar.jar"
  local start
  start=$(browser "$jar" -o /dev/null -w '%{redirect_url}' "$gateway/auth/oidc/start")
  [[ $start == "$idp/authorize?"* && $start == *code_challenge_method=S256* && $start == *nonce=* ]] || {
    echo "single sign-on did not redirect to the provider with PKCE and a nonce: $start" >&2
    return 1
  }
  local callback
  callback=$(browser "$jar" -o /dev/null -w '%{redirect_url}' "$start")
  browser "$jar" -o /dev/null -w '%{http_code}' "$callback"
}
[[ $(sso_sign_in carol) == 303 ]] || { echo "carol could not sign in with single sign-on" >&2; exit 1; }
me=$(api carol "$gateway/api/me")
[[ $(json 'json.load(sys.stdin)["name"]' <<<"$me") == carol && $(json 'json.load(sys.stdin)["kind"]' <<<"$me") == sso ]] || {
  echo "carol's single sign-on session is wrong: $me" >&2
  exit 1
}
[[ $(api carol -o /dev/null -w '%{http_code}' -X POST --data '{"name":"Team","max_devices":2}' "$gateway/api/clients") == 201 ]] || {
  echo "the operator could not create a client" >&2
  exit 1
}
printf 'mallory@example.com\n' >"$work/email"
[[ $(sso_sign_in mallory) == 403 ]] || { echo "an unknown single sign-on user became an administrator" >&2; exit 1; }
echo "single sign-on maps verified emails to administrators and refuses others"

# Users in an allowed domain sign in and get an account of their own.
user_sign_in() {
  local jar=$1
  rm -f "$work/$jar.jar"
  local start callback
  start=$(browser "$jar" -o /dev/null -w '%{redirect_url}' "$gateway/auth/sso/start")
  [[ $start == "$idp/authorize?"* && $start == *code_challenge_method=S256* ]] || {
    echo "user sign-in did not redirect to the provider: $start" >&2
    return 1
  }
  callback=$(browser "$jar" -o /dev/null -w '%{redirect_url}' "$start")
  browser "$jar" -o /dev/null -w '%{http_code} %{redirect_url}' "$callback"
}
# The token in the setup the downloads page offers the signed-in user.
setup_token() {
  browser "$1" "$gateway/portal/downloads" | python3 -c '
import html, re, sys, urllib.parse
setup = re.search(r"porta://profile\?[^\"]+", sys.stdin.read())
print(urllib.parse.parse_qs(html.unescape(setup.group(0)).split("?", 1)[1])["token"][0])'
}
accounts() {
  token_api http://127.0.0.1:9090/api/clients |
    json "[c for c in json.load(sys.stdin)['clients'] if c['name'] == '$1']"
}
grep -q 'href="/auth/sso/start"' <(browser probe "$gateway/access") || {
  echo "the access page does not offer user sign-in" >&2
  exit 1
}
printf 'Dana@Example.org\n' >"$work/email"
[[ $(user_sign_in dana) == "303 $gateway/portal/downloads" ]] || { echo "dana could not sign in" >&2; exit 1; }
first=$(setup_token dana)
[[ ${#first} -ge 16 ]] || { echo "the downloads page offers no setup after sign-in" >&2; exit 1; }
[[ $(user_sign_in dana-again) == "303 $gateway/portal/downloads" && $(setup_token dana-again) == "$first" ]] || {
  echo "signing in again did not show the same account" >&2
  exit 1
}
account=$(accounts dana@example.org)
[[ $(json 'len(eval(sys.stdin.read()))' <<<"$account") == 1 && $(json 'eval(sys.stdin.read())[0]["max_devices"]' <<<"$account") == 3 ]] || {
  echo "single sign-on did not create one account with the configured device limit: $account" >&2
  exit 1
}
dana_id=$(json 'eval(sys.stdin.read())[0]["id"]' <<<"$account")
token_api -X POST "http://127.0.0.1:9090/api/clients/$dana_id/token" >/dev/null
[[ $(user_sign_in dana-rotated) == "303 $gateway/portal/downloads" ]] || { echo "dana could not sign in after a rotation" >&2; exit 1; }
rotated=$(setup_token dana-rotated)
[[ $rotated != "$first" && ${#rotated} -ge 16 ]] || { echo "a rotated account showed its old token" >&2; exit 1; }
token_api -X PUT --data '{"name":"dana@example.org","max_devices":3,"enabled":false}' \
  "http://127.0.0.1:9090/api/clients/$dana_id" >/dev/null
[[ $(user_sign_in dana-disabled) == "403 " ]] || { echo "a disabled account signed in" >&2; exit 1; }
printf 'erin@example.net\n' >"$work/email"
[[ $(user_sign_in erin) == "403 " ]] || { echo "an email outside the allowed domains got an account" >&2; exit 1; }
[[ $(json 'len(eval(sys.stdin.read()))' <<<"$(accounts erin@example.net)") == 0 ]]
[[ $(stat -c %a "$work/state/sso-users.json") == 600 ]] || { echo "the single sign-on users are readable by others" >&2; exit 1; }
if grep -q "$rotated" "$work/state/sso-users.json"; then
  echo "the single sign-on users store a plaintext token" >&2
  exit 1
fi
echo "users in allowed domains sign in to an account of their own, which administrators control"

# Disabling an administrator ends what their sessions can do.
bob_id=$(token_api http://127.0.0.1:9090/api/admins | json 'next(a["id"] for a in json.load(sys.stdin)["admins"] if a["username"] == "bob")')
token_api -X PUT --data '{"disabled":true}' "http://127.0.0.1:9090/api/admins/$bob_id" >/dev/null
[[ $(api bob -o /dev/null -w '%{http_code}' -X POST --data '{}' "$gateway/api/clients") == 404 ]] || {
  echo "a disabled administrator's session still works" >&2
  exit 1
}

events=$(api alice "$gateway/api/audit?limit=100")
python3 - "$events" <<'PY'
import json, sys
events = json.loads(sys.argv[1])["events"]
def has(kind, name, action, outcome):
    return any(e["actor"]["kind"] == kind and e["actor"].get("name") == name and e["action"] == action and e["outcome"] == outcome for e in events)
assert has("admin", "alice", "admin.sign_in", "ok"), events
assert has("admin", "alice", "admin.sign_in", "denied"), events
assert has("sso", "carol", "admin.sign_in", "ok"), events
assert has("sso", "mallory@example.com", "admin.sign_in", "denied"), events
assert has("sso", "dana@example.org", "user.sign_in", "ok"), events
assert has("sso", "dana@example.org", "user.sign_in", "denied"), events
assert has("sso", "erin@example.net", "user.sign_in", "denied"), events
assert has("token", "break-glass token", "POST /api/admins", "ok"), events
assert has("admin", "bob", "POST /api/clients", "denied"), events
assert has("sso", "carol", "POST /api/clients", "ok"), events
assert has("token", "break-glass token", "PUT /api/admins/{admin}", "ok"), events
assert all("password" not in json.dumps(e) for e in events if e["action"].startswith("POST /api/admins"))
PY
[[ $(api alice "$gateway/api/audit/export" | wc -l) -ge 10 ]] || { echo "the audit export is incomplete" >&2; exit 1; }
[[ $(stat -c %a "$work/state/audit.log") == 600 && $(stat -c %a "$work/state/admins.json") == 600 ]] || {
  echo "the audit log or administrator store is readable by others" >&2
  exit 1
}
echo "the audit log records actors, actions, targets and outcomes"
echo "administrator identity test passed"
