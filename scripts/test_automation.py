#!/usr/bin/env python3
"""Run shell regressions without invoking host service or networking commands."""

import base64
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
MOCK = ROOT / "scripts/tests/mock_system.py"


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / (".automation-test-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.bin = self.root / "commands"
        self.bin.mkdir()
        (self.root / "scratch").mkdir()
        self.env = {
            **os.environ,
            "AUTOMATION_FIXTURE": str(self.root),
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "TMPDIR": str(self.root / "scratch"),
            "SUDO_USER": "",
            "GH_TOKEN": "",
            "GITHUB_TOKEN": "",
            "PORTA_RUNTIME_DIRECTORY": str(self.root / "runtime"),
        }
        self.write_state(
            sysctl={
                "net.core.rmem_max": "212992",
                "net.core.wmem_max": "212992",
                "net.ipv4.ip_forward": "0",
            }
        )
        for command in (
            "mktemp", "systemctl", "sysctl", "ip", "nft", "iptables", "openssl",
            "curl", "ss", "make", "mv", "git", "gomobile", "adb", "sleep", "gh", "uname",
        ):
            (self.bin / command).symlink_to(MOCK)

    def write_state(self, **values):
        (self.root / "state.json").write_text(json.dumps(values))

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def update_state(self, **values):
        self.write_state(**(self.state() | values))

    def commands(self):
        return [
            json.loads(line)
            for line in (self.root / "commands.jsonl").read_text().splitlines()
        ]

    def run_script(self, name, *args, success=True, cwd=None):
        result = subprocess.run(
            ["bash" if name.endswith(("deploy.sh", "server-up.sh", "server-down.sh",
                                      "check-version.sh", "build-android-aar.sh")) else "sh",
             str(ROOT / "scripts" / name), *map(str, args)],
            cwd=cwd or self.root, env=self.env, text=True, capture_output=True,
            timeout=30,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def certificate_pair(self, name, identity):
        certificate = self.root / (name + ".crt")
        key = self.root / (name + ".key")
        certificate.write_text("certificate:" + identity)
        key.write_text("key:" + identity)
        return certificate, key

    def assert_no_stages(self, directory):
        self.assertFalse([p for p in directory.glob(".sync.*") if p.is_dir()])

    def test_certificate_noop_and_permissions(self):
        cert, key = self.certificate_pair("source", "one")
        destination = self.root / "tls"
        self.run_script("sync-cert.sh", cert, key, destination)
        before = (destination / "server.crt").stat().st_mtime_ns
        self.run_script("sync-cert.sh", cert, key, destination)
        self.assertEqual(before, (destination / "server.crt").stat().st_mtime_ns)
        self.assertEqual((destination / "server.key").stat().st_mode & 0o777, 0o600)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assert_no_stages(destination)

    def test_certificate_mismatch_and_copy_failure_preserve_old_pair(self):
        cert, key = self.certificate_pair("source", "old")
        destination = self.root / "tls"
        self.run_script("sync-cert.sh", cert, key, destination)
        cert.write_text("certificate:new")
        self.run_script("sync-cert.sh", cert, key, destination, success=False)
        self.run_script("sync-cert.sh", cert, self.root / "missing", destination,
                        success=False)
        self.assertEqual((destination / "server.crt").read_text(), "certificate:old")
        self.assertEqual((destination / "server.key").read_text(), "key:old")
        self.assert_no_stages(destination)

    def test_certificate_second_rename_failure_rolls_back_pair(self):
        cert, key = self.certificate_pair("source", "old")
        destination = self.root / "tls"
        self.run_script("sync-cert.sh", cert, key, destination)
        cert.write_text("certificate:new")
        key.write_text("key:new")
        self.update_state(fail_key_move=True)
        self.run_script("sync-cert.sh", cert, key, destination, success=False)
        self.assertEqual((destination / "server.crt").read_text(), "certificate:old")
        self.assertEqual((destination / "server.key").read_text(), "key:old")
        self.assert_no_stages(destination)

    def test_certificate_sync_waits_for_exclusive_lock(self):
        cert, key = self.certificate_pair("source", "old")
        destination = self.root / "tls"
        self.run_script("sync-cert.sh", cert, key, destination)
        cert.write_text("certificate:new")
        key.write_text("key:new")
        with (destination / ".sync.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = subprocess.Popen(
                ["sh", str(ROOT / "scripts/sync-cert.sh"), str(cert), str(key),
                 str(destination)], env=self.env, cwd=self.root,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                time.sleep(0.5)
                self.assertIsNone(process.poll(), "sync ignored the existing lock")
                self.assertEqual((destination / "server.crt").read_text(), "certificate:old")
                self.assert_no_stages(destination)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual((destination / "server.key").read_text(), "key:new")

    def test_nft_rules_are_replaced_in_one_transaction(self):
        self.update_state(nft_table="old", nft_tables={"ip porta": "old", "inet porta_guard": "old"}, docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        transaction = self.state()["nft_transaction"]
        self.assertTrue(transaction.startswith("delete table ip porta\ndelete table inet porta_guard\n"))
        self.assertIn('iifname "porta0" drop', transaction)
        self.assertIn("ip saddr 10.66.0.0/24 masquerade", transaction)
        self.assertIn('iifname "eth0" meta nfproto ipv4 tcp dport 8443', transaction)
        self.assertIn('meter tcp4 size 65535', transaction)
        self.assertIn('meter udp6 size 65535', transaction)
        mutations = [call for call in self.commands() if call[:2] == ["nft", "-f"]]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(len(self.state()["iptables_rules"]), 2)

    def test_mock_pipeline_preserves_concurrent_state_and_atomic_snapshots(self):
        self.update_state(nft_table="old")
        transaction = "delete table ip porta\ntable ip porta {}\n"
        with subprocess.Popen(
            [str(self.bin / "nft"), "-f", "-"], cwd=self.root, env=self.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        ) as consumer:
            try:
                deadline = time.monotonic() + 5
                while not (self.root / "commands.jsonl").exists():
                    self.assertIsNone(consumer.poll())
                    if time.monotonic() >= deadline:
                        self.fail("nft mock did not start")
                    time.sleep(0.01)
                # The consumer has read state, but cannot finish until we close
                # stdin. Its producer must be able to run other mock commands.
                before = self.state()
                with (self.root / "state.json").open() as snapshot:
                    producer = subprocess.run(
                        [str(self.bin / "sysctl"), "-w", "net.ipv4.ip_forward=1"],
                        cwd=self.root, env=self.env, capture_output=True, text=True,
                        timeout=5,
                    )
                    self.assertEqual(producer.returncode, 0,
                                     producer.stdout + producer.stderr)
                    self.assertEqual(json.load(snapshot), before,
                                     "saving state truncated an existing reader's snapshot")
                stdout, stderr = consumer.communicate(transaction, timeout=5)
                self.assertEqual(consumer.returncode, 0, stdout + stderr)
            finally:
                if consumer.poll() is None:
                    consumer.kill()
                consumer.communicate()
        self.assertEqual(self.state()["sysctl"]["net.ipv4.ip_forward"], "1")
        self.assertEqual(self.state()["nft_table"], transaction)
        self.assertCountEqual(self.commands(), [
            ["nft", "-f", "-"], ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ])

    def test_mock_nested_command_reloads_state_without_deadlock(self):
        self.prepare_deploy()
        unit = self.root / "system/etc/systemd/system/porta-cert-sync.service"
        unit.write_text(f"ExecStart={self.bin / 'systemctl'} enable nested.service\n")
        result = subprocess.run(
            [str(self.bin / "systemctl"), "start",
             "porta-cert-sync.service", "other.service"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state()["enabled"]["nested.service"], "enabled")
        self.assertFalse(self.state()["active"]["porta-cert-sync.service"])
        self.assertTrue(self.state()["active"]["other.service"])

    def test_nft_failure_preserves_previous_table(self):
        old_tables = {"ip porta": "old", "inet porta_guard": "old guard"}
        self.update_state(nft_table="old", nft_tables=old_tables, fail_nft=True, docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443", success=False)
        self.assertEqual(self.state()["nft_table"], "old")
        self.assertEqual(self.state()["nft_tables"], old_tables)
        self.assertFalse(any(call[0] == "iptables" for call in self.commands()))

    def test_nft_setup_rejects_invalid_public_port_before_mutation(self):
        for port in ("0", "65536", "not-a-port"):
            with self.subTest(port=port):
                self.run_script(
                    "server-up.sh", "porta0", "10.66.0.1/24",
                    "10.66.0.0/24", "eth0", port, success=False,
                )
        self.assertFalse((self.root / "commands.jsonl").exists())

    def test_automatic_mtu_scopes_icmp_acceptance_to_owned_tun(self):
        self.run_script("server-up.sh", "porta.0", "10.66.0.1/24",
                        "10.66.0.0/24", "eth0", "8443")
        calls = self.commands()
        self.assertIn(["sysctl", "-w", "net/ipv4/conf/porta.0/accept_local=1"], calls)
        self.assertIn(["sysctl", "-w", "net/ipv4/conf/porta.0/rp_filter=2"], calls)
        ipv4_changes = [call[2] for call in calls
                        if call[:2] == ["sysctl", "-w"] and "/ipv4/conf/" in call[2]]
        self.assertEqual(len(ipv4_changes), 2)
        self.assertTrue(all("/porta.0/" in value for value in ipv4_changes))

    def test_fixed_mtu_does_not_change_source_validation(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443", "--auto-mtu=false")
        self.assertFalse(any("accept_local" in " ".join(call) or "rp_filter" in " ".join(call)
                             for call in self.commands()))

    def test_ipv6_sysctl_preserves_dots_in_interface_name(self):
        proc = self.root / "proc/sys"
        setting = proc / "net/ipv6/conf/porta.0/disable_ipv6"
        setting.parent.mkdir(parents=True)
        setting.touch()
        script = self.root / "server-up.sh"
        script.write_text((ROOT / "scripts/server-up.sh").read_text().replace(
            "/proc/sys", str(proc)
        ))
        self.run_script(str(script), "porta.0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        self.assertIn(["sysctl", "-w", "net/ipv6/conf/porta.0/disable_ipv6=1"],
                      self.commands())

    def test_down_removes_duplicates_and_is_idempotent(self):
        self.update_state(nft_table="old", nft_tables={"ip porta": "old", "inet porta_guard": "old"}, docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        self.update_state(iptables_rules=self.state()["iptables_rules"] * 2)
        self.run_script("server-down.sh", "porta0", "eth0")
        self.run_script("server-down.sh", "porta0", "eth0")
        self.assertEqual(self.state()["iptables_rules"], [])
        self.assertEqual(self.state()["nft_table"], "")
        self.assertEqual(self.state()["nft_tables"], {})

    def test_down_uses_tracked_external_interface_for_docker_cleanup(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.run_script("server-down.sh", "porta0")
        self.assertEqual(self.state()["iptables_rules"], [])
        self.assertFalse((self.root / "runtime/docker-rules-porta0").exists())

    def test_docker_marker_survives_indeterminate_rule_check(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.update_state(fail_iptables_check=True)
        self.run_script("server-down.sh", "porta0", success=False)
        self.assertTrue((self.root / "runtime/docker-rules-porta0").exists())
        self.assertEqual(len(self.state()["iptables_rules"]), 2)

    def test_server_up_reconciles_previous_docker_interface(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "wan0", "8443")
        rules = self.state()["iptables_rules"]
        self.assertEqual(len(rules), 2)
        self.assertTrue(all("wan0" in rule and "eth0" not in rule for rule in rules))
        self.assertEqual((self.root / "runtime/docker-rules-porta0").read_text(), "wan0\n")

    def test_partial_docker_reconciliation_keeps_all_interfaces_tracked(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.update_state(fail_iptables_insert="2")
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "wan0", "8443", success=False)
        marker = (self.root / "runtime/docker-rules-porta0").read_text().splitlines()
        self.assertCountEqual(marker, ["eth0", "wan0"])
        self.update_state(fail_iptables_insert="")
        self.run_script("server-down.sh", "porta0")
        self.assertEqual(self.state()["iptables_rules"], [])

    def test_down_restores_original_forwarding_state(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.assertEqual(self.state()["sysctl"]["net.ipv4.ip_forward"], "1")
        self.run_script("server-down.sh", "porta0", "eth0")
        self.assertEqual(self.state()["sysctl"]["net.ipv4.ip_forward"], "0")
        self.assertFalse((self.root / "runtime/ip-forward-porta0").exists())

        self.update_state(sysctl=self.state()["sysctl"] | {"net.ipv4.ip_forward": "1"})
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.run_script("server-down.sh", "porta0", "eth0")
        self.assertEqual(self.state()["sysctl"]["net.ipv4.ip_forward"], "1")

    def test_down_reports_failed_table_deletion(self):
        old_tables = {"ip porta": "old", "inet porta_guard": "old guard"}
        self.update_state(nft_table="old", nft_tables=old_tables, fail_nft=True)
        self.run_script("server-down.sh", "porta0", "eth0", success=False)
        self.assertEqual(self.state()["nft_table"], "old")
        self.assertEqual(self.state()["nft_tables"], old_tables)
        self.assertIn(["ip", "link", "set", "dev", "porta0", "down"], self.commands())

    def version_file(self, value):
        path = self.root / "internal/buildinfo/VERSION"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n")

    def test_version_requires_canonical_patch(self):
        for value in ("0.1.0", "0.1.4", "0.1.999"):
            self.version_file(value)
            self.run_script("check-version.sh")
        for value in ("0.1.04", "0.1.000", "0.1.1000", "0.2.1", "bad"):
            self.version_file(value)
            self.run_script("check-version.sh", success=False)

    def test_version_invalid_base_is_not_silently_ignored(self):
        self.version_file("0.1.4")
        self.update_state(missing_revision=True)
        self.run_script("check-version.sh", "missing", success=False)
        self.run_script("check-version.sh", "00000000000000000000")

    def test_version_checks_existing_base_and_allows_initial_introduction(self):
        self.version_file("0.1.4")
        self.run_script("check-version.sh", "base")
        self.update_state(previous_version="0.1.4")
        self.run_script("check-version.sh", "base", success=False)
        self.update_state(previous_version="")
        self.run_script("check-version.sh", "base", success=False)
        self.update_state(missing_previous_file=True)
        self.run_script("check-version.sh", "base")

    def test_android_relative_output_uses_callers_directory(self):
        ndk = self.root / "ndk"
        ndk.mkdir()
        self.env.update(ANDROID_NDK_HOME=str(ndk), GOMOBILE=str(self.bin / "gomobile"))
        self.run_script("build-android-aar.sh", "nested/output.aar")
        self.assertEqual((self.root / "nested/output.aar").read_text(), "aar")

    def test_android_soak_restores_wifi_after_failure(self):
        self.update_state(fail_sleep=True)
        self.run_script("android-soak.sh", "1", success=False)
        wifi = [call for call in self.commands() if call[:4] == ["adb", "shell", "svc", "wifi"]]
        self.assertEqual([call[-1] for call in wifi], ["disable", "enable"])

    def test_android_soak_rejects_invalid_cycle_count(self):
        for value in ("bad", "-1", "0"):
            self.run_script("android-soak.sh", value, success=False)
        self.assertFalse((self.root / "commands.jsonl").exists())

    def test_android_soak_rejects_another_apps_vpn(self):
        self.update_state(porta_service=False)
        self.run_script("android-soak.sh", "1", success=False)

    def prepare_deploy(self, existing=True, timer=True):
        checkout = self.root / "checkout"
        shutil.copytree(ROOT / "scripts", checkout / "scripts")
        shutil.copytree(ROOT / "deploy", checkout / "deploy")
        source = (checkout / "scripts/deploy.sh").read_text()
        for prefix in (
            "/usr/local/bin", "/usr/local/libexec/porta", "/etc/porta",
            "/etc/sysctl.d", "/etc/systemd/system", "/var/lib/porta", "/run/lock",
        ):
            source = source.replace(prefix, str(self.root / "system" / prefix[1:]))
        source = source.replace("[[ $EUID -eq 0 ]]", "true")
        deploy = checkout / "scripts/deploy.sh"
        deploy.write_text(source)
        for directory in (
            "usr/local/bin", "usr/local/libexec/porta", "etc/porta/tls",
            "etc/porta/landing", "etc/sysctl.d", "etc/systemd/system",
            "var/lib/porta/downloads", "run/lock",
        ):
            (self.root / "system" / directory).mkdir(parents=True, exist_ok=True)
        if existing:
            files = {
                "usr/local/bin/porta-server": "old server",
                "usr/local/libexec/porta/server-up.sh": "old up",
                "usr/local/libexec/porta/server-down.sh": "old down",
                "usr/local/libexec/porta/sync-cert.sh": "old sync",
                "etc/sysctl.d/99-porta-quic.conf": "old sysctl",
                "etc/porta/porta.env": "PORTA_TOKEN=old-client\nPORTA_ADMIN_TOKEN=old-admin\n",
                "etc/porta/tls/server.crt": "certificate:old",
                "etc/porta/tls/server.key": "key:old",
                "etc/porta/landing/custom.html": "<h1>custom landing</h1>",
                "etc/systemd/system/porta.service": "old service --acme-domain old.example\n",
                "var/lib/porta/downloads/CLIENT_VERSION": "v0.1.3",
                "var/lib/porta/downloads/old-client": "old client",
                "var/lib/porta/leases.json": '{"leases":{"old":"10.66.0.2"}}',
                "var/lib/porta/clients.json": '{"old":"client"}',
                "var/lib/porta/usage.json": '{"old":"usage"}',
            }
            if timer:
                files |= {
                    "etc/systemd/system/porta-cert-sync.service": "old sync service",
                    "etc/systemd/system/porta-cert-sync.timer": "old timer",
                }
            for filename, text in files.items():
                (self.root / "system" / filename).write_text(text)
        self.update_state(
            active={"porta.service": existing, "porta-cert-sync.timer": existing and timer},
            enabled={"porta.service": "enabled" if existing else "disabled",
                     "porta-cert-sync.timer": "enabled" if existing and timer else "disabled"},
        )
        return deploy

    def run_deploy(self, deploy, *options, success=True):
        result = subprocess.run(
            ["bash", str(deploy), "--domain", "vpn.example", "--external-interface", "eth0",
             *map(str, options)], cwd=self.root, env=self.env, text=True,
            capture_output=True, timeout=60,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def snapshot(self):
        return {
            str(path.relative_to(self.root / "system")): path.read_bytes()
            for path in (self.root / "system").rglob("*")
            if path.is_file() and path.name not in ("porta-deploy.lock", ".sync.lock")
        }

    def test_deploy_health_failure_restores_stopped_state_tls_and_enablement(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        original_sysctl = self.state()["sysctl"]
        cert, key = self.certificate_pair("source", "new")
        self.update_state(fail_health=True, flush_on_stop=True)
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key,
                        "--reset-leases", success=False)
        before["var/lib/porta/leases.json"] = json.dumps(
            {"leases": {"flushed": "10.66.0.3"}}
        ).encode()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.state()["sysctl"], original_sysctl)
        self.assertTrue(self.state()["active"]["porta.service"])
        self.assertTrue(self.state()["active"]["porta-cert-sync.timer"])
        self.assertEqual(self.state()["enabled"]["porta-cert-sync.timer"], "enabled")
        self.assertEqual(self.state()["stopped_helpers"][0], "old down")
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_deploy_public_redirect_rolls_back(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        cert, key = self.certificate_pair("source", "new")
        self.update_state(public_status="302")
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key,
                        success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.state()["active"]["porta.service"])

    def test_failed_static_to_acme_upgrade_restores_certificate_timer(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.update_state(fail_start=True)
        self.run_deploy(deploy, "--build-local", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.state()["active"]["porta-cert-sync.timer"])
        self.assertEqual(self.state()["enabled"]["porta-cert-sync.timer"], "enabled")

    def test_failed_upgrade_preserves_inactive_runtime_enabled_service(self):
        deploy = self.prepare_deploy(timer=False)
        before = self.snapshot()
        self.update_state(
            active={"porta.service": False, "porta-cert-sync.timer": False},
            enabled={"porta.service": "enabled-runtime", "porta-cert-sync.timer": "disabled"},
            fail_health=True,
        )
        self.run_deploy(deploy, "--build-local", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.state()["active"]["porta.service"])
        self.assertFalse(self.state()["active"]["porta-cert-sync.timer"])
        self.assertEqual(self.state()["enabled"]["porta.service"], "enabled-runtime")

    def test_failed_new_install_removes_credentials_and_disables_units(self):
        deploy = self.prepare_deploy(existing=False)
        cert, key = self.certificate_pair("source", "new")
        self.update_state(fail_health=True)
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key, success=False)
        self.assertEqual(self.snapshot(), {})
        self.assertFalse(self.state()["active"]["porta.service"])
        self.assertFalse(self.state()["active"]["porta-cert-sync.timer"])
        self.assertEqual(self.state()["enabled"]["porta.service"], "disabled")
        self.assertEqual(self.state()["enabled"]["porta-cert-sync.timer"], "disabled")

    def test_successful_upgrade_preserves_credentials_and_stops_old_helpers_first(self):
        deploy = self.prepare_deploy(timer=False)
        cert, key = self.certificate_pair("source", "new")
        environment = (self.root / "system/etc/porta/porta.env").read_bytes()
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key,
                        "--port", "08443", "--admin-port", "00081",
                        "--trust-proxy-headers")
        self.assertEqual((self.root / "system/etc/porta/porta.env").read_bytes(), environment)
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--listen :8443", unit)
        self.assertIn("--admin-listen 127.0.0.1:81", unit)
        self.assertIn("--egress-interface eth0", unit)
        self.assertIn("--mtu 1400", unit)
        self.assertIn("--auto-mtu=true", unit)
        self.assertIn("--landing-template-dir", unit)
        self.assertIn("--trust-proxy-headers", unit)
        self.assertTrue((self.root / "system/etc/porta/landing").is_dir())
        self.assertEqual(
            (self.root / "system/etc/porta/landing/custom.html").read_text(),
            "<h1>custom landing</h1>",
        )
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443 --auto-mtu=true", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE", unit)
        self.assertEqual(self.state()["stopped_helpers"][0], "old down")
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_deploy_automatic_mtu_preserves_custom_ceiling(self):
        deploy = self.prepare_deploy(timer=False)
        self.run_deploy(deploy, "--build-local", "--auto-mtu", "--mtu", "1280")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--auto-mtu=true", unit)
        self.assertIn("--mtu 1280", unit)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443 --auto-mtu=true", unit)

    def test_deploy_fixed_mtu_disables_discovery_and_helper_settings(self):
        deploy = self.prepare_deploy(timer=False)
        self.run_deploy(deploy, "--build-local", "--auto-mtu=false", "--mtu", "1100")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--auto-mtu=false", unit)
        self.assertNotIn("--auto-mtu=true", unit)
        self.assertIn("--mtu 1100", unit)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443 --auto-mtu=false", unit)

    def test_bundled_service_uses_automatic_mtu_defaults(self):
        unit = (ROOT / "deploy/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        setup = next(line for line in unit.splitlines() if line.startswith("ExecStartPost="))
        self.assertIn("--auto-mtu=true", start)
        self.assertIn("--mtu 1400", unit)
        self.assertIn("--landing-template-dir /etc/porta/landing", start)
        self.assertIn("--auto-mtu=true", setup)
        self.assertIn("eth0 8443 --auto-mtu=true", setup)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)

    def test_acme_rejects_admin_port_80_before_stopping_service(self):
        deploy = self.prepare_deploy()
        self.run_deploy(deploy, "--build-local", "--admin-port", "80", success=False)
        self.assertNotIn("stopped_helpers", self.state())

    def test_deploy_rejects_invalid_dns_names_before_stopping_service(self):
        deploy = self.prepare_deploy()
        for domain in ("vpn..example.com", "-vpn.example.com", "vpn-.example.com",
                       "vpn_test.example.com", "192.0.2.1"):
            with self.subTest(domain=domain):
                self.run_deploy(deploy, "--build-local", "--domain", domain, success=False)
        self.assertNotIn("stopped_helpers", self.state())

    def test_deploy_rejects_unsafe_canonical_certificate_paths(self):
        deploy = self.prepare_deploy()
        unsafe_directory = self.root / "certificate directory"
        unsafe_directory.mkdir()
        certificate, key = self.certificate_pair("certificate directory/server", "new")
        certificate_link = self.root / "server.crt"
        key_link = self.root / "server.key"
        certificate_link.symlink_to(certificate)
        key_link.symlink_to(key)
        self.run_deploy(deploy, "--build-local", "--cert", certificate_link,
                        "--key", key_link, success=False)
        self.assertNotIn("stopped_helpers", self.state())

    def release_assets(self, landing_templates=True, proxy_headers=True):
        release = self.root / "release"
        release.mkdir()
        assets = [
            "porta-server-linux-amd64", "porta-client-linux-amd64",
            "porta-client-linux-arm64", "porta-client-windows-amd64.zip",
            "porta-android-arm64-v8a.apk", "porta-android-armeabi-v7a.apk",
            "porta-android-x86_64.apk",
        ]
        checksums = []
        for name in assets:
            if name.startswith("porta-server"):
                features = "client-downloads\\n"
                if proxy_headers:
                    features += "trust-proxy-headers\\n"
                if landing_templates:
                    features += "landing-template-dir\\n"
                data = f"#!/bin/sh\nprintf '{features}'\n".encode()
            else:
                data = name.encode()
            (release / name).write_bytes(data)
            checksums.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        (release / "SHA256SUMS").write_text("".join(checksums))
        assets.append("SHA256SUMS")
        (release / "release.json").write_text(json.dumps({
            "tag_name": "v0.1.4",
            "assets": [{"name": name, "url": f"https://api.github.com/mock-assets/{name}"}
                       for name in assets],
        }))

    def test_release_upgrade_publishes_complete_download_set(self):
        deploy = self.prepare_deploy()
        self.release_assets()
        self.run_deploy(deploy)
        downloads = self.root / "system/var/lib/porta/downloads"
        self.assertEqual((downloads / "CLIENT_VERSION").read_text(), "v0.1.4\n")
        self.assertTrue((downloads / "porta-client-windows-amd64.zip").is_file())
        self.assertFalse((downloads / "old-client").exists())
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_release_token_is_not_exposed_in_curl_arguments(self):
        deploy = self.prepare_deploy()
        self.release_assets()
        self.env["GH_TOKEN"] = "secret-test-token"
        self.run_deploy(deploy)
        curl_calls = [call for call in self.commands() if call[0] == "curl"]
        self.assertTrue(curl_calls)
        self.assertNotIn("secret-test-token", json.dumps(curl_calls))

    def test_release_without_landing_templates_fails_before_stopping_service(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets(landing_templates=False)
        self.run_deploy(deploy, success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("stopped_helpers", self.state())

    def test_release_without_proxy_header_support_fails_only_when_requested(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets(proxy_headers=False)
        self.run_deploy(deploy, "--trust-proxy-headers", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("stopped_helpers", self.state())

    def test_download_checksum_failure_leaves_installation_untouched(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets()
        (self.root / "release/porta-client-linux-amd64").write_text("corrupt")
        self.run_deploy(deploy, success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("stopped_helpers", self.state())
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_failed_release_upgrade_restores_previous_downloads(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets()
        self.update_state(fail_health=True)
        self.run_deploy(deploy, success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list((self.root / "scratch").iterdir()), [])
        self.assertFalse(list((self.root / "system/var/lib/porta").glob("downloads.new.*")))

    def release_script(self, name):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        step = workflow.split(f"      - name: {name}\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        script = step.split("        run: ", 1)[1]
        if script.startswith("|\n"):
            return "\n".join(line[10:] for line in script[2:].splitlines())
        return script.strip()

    def test_workflows_pin_actions_and_gradle_distribution(self):
        action_reference = re.compile(r"^[^@\s]+@[0-9a-f]{40}(?:\s+#\s+v\S+)?$")
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            for line in workflow.read_text().splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].strip()
                self.assertRegex(reference, action_reference, f"mutable action in {workflow}")
        wrapper = (ROOT / "android/gradle/wrapper/gradle-wrapper.properties").read_text()
        self.assertRegex(wrapper, r"(?m)^distributionSha256Sum=[0-9a-f]{64}$")

    def signing_environment(self):
        return self.env | {
            "RUNNER_TEMP": str(self.root / "scratch"),
            "GITHUB_ENV": str(self.root / "github.env"),
            "KEYSTORE_BASE64": base64.b64encode(b"signing-fixture").decode(),
            "KEYSTORE_PASSWORD": "test-only",
            "KEY_ALIAS": "porta",
            "KEY_PASSWORD": "test-only",
        }

    def test_release_requires_complete_signing_secrets(self):
        for name in ("KEYSTORE_BASE64", "KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD"):
            with self.subTest(missing=name):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     self.release_script("Prepare persistent Android signing key")],
                    cwd=self.root, env=self.signing_environment() | {name: ""},
                    text=True, capture_output=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("All four PORTA_ANDROID signing secrets are required", result.stderr)
                self.assertFalse((self.root / "scratch/porta-release.p12").exists())

    def test_release_prepares_private_signing_store_and_removes_it(self):
        environment = self.signing_environment()
        result = subprocess.run(
            ["bash", "-euo", "pipefail", "-c",
             self.release_script("Prepare persistent Android signing key")],
            cwd=self.root, env=environment, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        store = self.root / "scratch/porta-release.p12"
        self.assertEqual(store.read_bytes(), b"signing-fixture")
        self.assertEqual(store.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "github.env").read_text(),
                         f"PORTA_ANDROID_KEYSTORE={store}\n")
        subprocess.run(
            ["bash", "-euo", "pipefail", "-c",
             self.release_script("Remove temporary Android signing key")],
            cwd=self.root, env=environment, check=True, capture_output=True, timeout=10,
        )
        self.assertFalse(store.exists())

    def test_release_verifies_apk_signature_and_exact_signer(self):
        fingerprint = "a" * 64
        (self.root / "signing-certificate.sha256").write_text(fingerprint + "\n")
        gradle = self.root / "gradlew"
        gradle.write_text("#!/bin/sh\nexit 0\n")
        gradle.chmod(0o755)
        apksigner = self.root / "sdk/build-tools/35.0.0/apksigner"
        apksigner.parent.mkdir(parents=True)
        apksigner.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$APK_SIGNER_OUTPUT"\nexit "$APK_VERIFY_STATUS"\n'
        )
        apksigner.chmod(0o755)
        apk = self.root / "app/build/outputs/apk/release/app-arm64-v8a-release.apk"
        apk.parent.mkdir(parents=True)
        apk.touch()
        good = f"Signer #1 certificate SHA-256 digest: {fingerprint}"
        cases = (
            ("valid", good, "0", True),
            ("wrong key", good.replace(fingerprint, "b" * 64), "0", False),
            ("additional signer", good + "\nSigner #2 certificate SHA-256 digest: "
             + "b" * 64, "0", False),
            ("invalid signature", good, "1", False),
        )
        for name, output, status, success in cases:
            with self.subTest(case=name):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     self.release_script("Build Android release")],
                    cwd=self.root, env=self.env | {
                        "ANDROID_HOME": str(self.root / "sdk"),
                        "APK_SIGNER_OUTPUT": output,
                        "APK_VERIFY_STATUS": status,
                    }, text=True, capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def publish_release(self, success=True):
        result = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", self.release_script("Publish GitHub release")],
            cwd=self.root,
            env=self.env | {"GITHUB_REF_NAME": "v0.1.4"},
            text=True, capture_output=True, timeout=10,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_release_is_not_published_until_all_uploads_succeed(self):
        self.update_state(fail_upload=True)
        self.publish_release(success=False)
        self.assertTrue(self.state()["release_draft"])
        self.assertFalse(any(call[:3] == ["gh", "release", "edit"]
                             for call in self.commands()))
        self.update_state(fail_upload=False)
        self.publish_release()
        self.assertFalse(self.state()["release_draft"])
        self.assertTrue(self.state()["assets_uploaded"])

    def test_published_release_is_not_overwritten_on_rerun(self):
        self.update_state(release_draft=False)
        self.publish_release(success=False)
        self.assertEqual(len(self.commands()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
