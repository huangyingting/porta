#!/usr/bin/env python3
"""Command doubles used only inside test_automation.py's isolated checkout."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import uuid


root = Path(os.environ["AUTOMATION_FIXTURE"]).resolve()
state_path = root / "state.json"
state_lock = (root / "state.lock").open("a")
name = Path(sys.argv[0]).name
args = sys.argv[1:]
code = 0


def safe(path):
    result = Path(path).resolve()
    if not result.is_relative_to(root):
        raise RuntimeError(f"mock refused path outside fixture: {result}")
    return result


def load():
    fcntl.flock(state_lock, fcntl.LOCK_EX)
    return json.loads(state_path.read_text())


def save():
    replacement = state_path.with_suffix(".json.new")
    replacement.write_text(json.dumps(state))
    os.replace(replacement, state_path)


@contextmanager
def unlocked_state():
    global state
    # Pipeline producers and nested mocks need this same lock to make progress.
    save()
    fcntl.flock(state_lock, fcntl.LOCK_UN)
    try:
        yield
    finally:
        state = load()


state = load()
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps([name, *args]) + "\n")


if name == "mktemp":
    directory = "-d" in args
    templates = [arg for arg in args if arg != "-d"]
    template = templates[0] if templates else str(root / "scratch" / "stage.XXXXXX")
    path = safe(template.replace("XXXXXX", uuid.uuid4().hex))
    if directory:
        path.mkdir(mode=0o700)
    else:
        path.touch(mode=0o600, exist_ok=False)
    print(path)
elif name == "systemctl":
    operation = args[0]
    units = [arg for arg in args[1:] if not arg.startswith("-")]
    active = state.setdefault("active", {})
    enabled = state.setdefault("enabled", {})
    if operation == "is-active":
        code = 0 if active.get(units[0], False) else 3
    elif operation == "is-enabled":
        value = enabled.get(units[0], "disabled")
        print(value)
        code = 0 if value.startswith("enabled") else 1
    elif operation == "cat":
        if units[0] == "docker.service":
            code = 1
        else:
            unit_path = root / "system/etc/systemd/system" / units[0]
            if unit_path.exists():
                print(unit_path.read_text())
            else:
                code = 1
    elif operation in ("stop", "start", "restart", "enable", "disable"):
        for unit in units:
            if operation in ("enable", "disable"):
                enabled[unit] = (
                    "enabled-runtime" if "--runtime" in args else "enabled"
                ) if operation == "enable" else "disabled"
                if "--now" not in args:
                    continue
            starting = operation in ("start", "restart")
            if unit == "porta.service" and not starting:
                helper = root / "system/usr/local/libexec/porta/server-down.sh"
                state.setdefault("stopped_helpers", []).append(
                    helper.read_text() if helper.exists() else None
                )
                if state.pop("flush_on_stop", False):
                    (root / "system/var/lib/porta/leases.json").write_text(
                        json.dumps({"leases": {"flushed": "10.66.0.3"}})
                    )
            if starting and unit == "porta.service":
                unit_text = (root / "system/etc/systemd/system/porta.service").read_text()
                if "Description=Porta VPN gateway" in unit_text:
                    state["new_started"] = True
                    for filename in ("leases.json", "clients.json", "usage.json"):
                        (root / "system/var/lib/porta" / filename).write_text("{}")
                    if state.pop("fail_start", False):
                        code = 1
            active[unit] = starting and code == 0
            if starting and unit == "porta-cert-sync.service":
                unit_path = root / "system/etc/systemd/system" / unit
                command = next(
                    line.removeprefix("ExecStart=")
                    for line in unit_path.read_text().splitlines()
                    if line.startswith("ExecStart=")
                )
                with unlocked_state():
                    code = subprocess.run(shlex.split(command), check=False).returncode
                active = state["active"]
                enabled = state["enabled"]
                active[unit] = False
    elif operation != "daemon-reload":
        raise RuntimeError(f"unexpected systemctl call: {args}")
elif name == "sysctl":
    values = state.setdefault("sysctl", {})
    if args[0] == "-n":
        print(values[args[1]])
    elif args[0] == "-w":
        key, value = args[1].split("=", 1)
        values[key] = value
    elif args[0] == "-p":
        for line in safe(args[1]).read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
elif name == "ip":
    if args[:4] == ["-4", "route", "show", "default"]:
        print("default via 192.0.2.1 dev eth0")
elif name == "nft":
    if args[:2] == ["list", "table"]:
        code = 0 if state.get("nft_table") else 1
    elif args == ["-f", "-"]:
        with unlocked_state():
            transaction = sys.stdin.read()
        state["nft_transaction"] = transaction
        if state.get("fail_nft"):
            code = 1
        else:
            state["nft_table"] = transaction
    elif args[:2] == ["delete", "table"]:
        if state.get("fail_nft"):
            code = 1
        else:
            state["nft_table"] = ""
    else:
        raise RuntimeError(f"nontransactional nft invocation: {args}")
elif name == "iptables":
    args = [arg for arg in args if arg != "-w"]
    operation = args[0]
    if operation == "-S":
        code = 0 if state.get("docker") else 1
    else:
        rules = state.setdefault("iptables_rules", [])
        rule = args[2:] if operation != "-I" else args[3:]
        if operation == "-C":
            code = 0 if rule in rules else 1
        elif operation == "-I":
            rules.append(rule)
        elif operation == "-D":
            rules.remove(rule)
        else:
            raise RuntimeError(f"unexpected iptables operation: {args}")
elif name == "openssl":
    if args[:2] == ["rand", "-hex"]:
        print("a" * 64)
    elif "-checkhost" in args:
        pass
    else:
        path = safe(args[args.index("-in") + 1])
        if state.get("slow_openssl"):
            time.sleep(0.1)
        print(path.read_text().strip().split(":")[-1])
elif name == "curl":
    url = next(arg for arg in args if arg.startswith(("http://", "https://")))
    if "--write-out" in args:
        if state.get("fail_health"):
            code = 22
        else:
            output_format = args[args.index("--write-out") + 1]
            output = output_format.replace(
                "%{http_code}", state.get("public_status", "200")
            ).replace(
                "%{content_type}",
                state.get("public_content_type", "text/html; charset=utf-8"),
            )
            print(output, end="")
    elif "--output" in args:
        output = safe(args[args.index("--output") + 1])
        asset = "release.json" if "/releases/" in url else url.rsplit("/", 1)[1]
        if asset == state.get("fail_download"):
            code = 22
        else:
            shutil.copyfile(root / "release" / asset, output)
    elif url.startswith("https://"):
        if state.get("fail_health"):
            code = 22
        else:
            print("<title>Porta</title>")
elif name == "gh":
    if args[:2] == ["release", "view"]:
        if "release_draft" not in state:
            code = 1
        else:
            print("true" if state["release_draft"] else "false")
    elif args[:2] == ["release", "create"]:
        state["release_draft"] = "--draft" in args
    elif args[:2] == ["release", "upload"]:
        code = 1 if state.get("fail_upload") else 0
        if not code:
            state["assets_uploaded"] = True
    elif args[:2] == ["release", "edit"]:
        if not state.get("assets_uploaded"):
            raise RuntimeError("publishing before assets were uploaded")
        state["release_draft"] = False
    else:
        raise RuntimeError(f"unexpected gh invocation: {args}")
elif name == "ss":
    if state.get("active", {}).get("porta.service") and "sport = :80" not in args:
        print('LISTEN users:(("porta-server",pid=123,fd=1))')
elif name == "make":
    binary = safe(Path.cwd() / "bin/porta-server")
    binary.parent.mkdir(exist_ok=True)
    binary.write_text("#!/bin/sh\nprintf 'client-downloads\\nlanding-template-dir\\n'\n")
    binary.chmod(0o755)
elif name == "mv":
    source, destination = map(safe, args[-2:])
    if (
        state.get("fail_key_move")
        and (source.name == "server.key.new"
             or (source.name == "server.key" and source.parent.name.startswith(".sync.")))
    ):
        state["fail_key_move"] = False
        code = 1
    else:
        os.replace(source, destination)
elif name == "git":
    if args[0] == "rev-parse":
        if state.get("missing_revision"):
            code = 128
        else:
            print("a" * 40)
    elif args[0] == "cat-file":
        code = 1 if state.get("missing_previous_file") else 0
    elif args[0] == "show":
        print(state.get("previous_version", "0.1.3"))
    else:
        raise RuntimeError(f"unexpected git invocation: {args}")
elif name == "gomobile":
    output = safe(args[args.index("-o") + 1])
    output.write_text("aar")
elif name == "adb":
    if args == ["shell", "dumpsys", "connectivity"]:
        print("TRANSPORT_VPN")
elif name == "sleep":
    code = 1 if state.get("fail_sleep") else 0
elif name == "uname":
    print("x86_64")
else:
    raise RuntimeError(f"unexpected mocked command: {name}")

save()
state_lock.close()
sys.exit(code)
