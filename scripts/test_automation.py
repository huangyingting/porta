#!/usr/bin/env python3
"""Run shell regressions without invoking host service or networking commands."""

import base64
import hashlib
import fcntl
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import threading
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
            "sudo", "unshare",
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
                                      "check-version.sh", "build-android-aar.sh",
                                      "test-server-firewall.sh")) else "sh",
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

    def test_mtu_feedback_scopes_icmp_acceptance_to_owned_tun(self):
        self.run_script("server-up.sh", "porta.0", "10.66.0.1/24",
                        "10.66.0.0/24", "eth0", "8443")
        calls = self.commands()
        self.assertIn(["sysctl", "-w", "net/ipv4/conf/porta.0/accept_local=1"], calls)
        self.assertIn(["sysctl", "-w", "net/ipv4/conf/porta.0/rp_filter=2"], calls)
        ipv4_changes = [call[2] for call in calls
                        if call[:2] == ["sysctl", "-w"] and "/ipv4/conf/" in call[2]]
        self.assertEqual(len(ipv4_changes), 2)
        self.assertTrue(all("/porta.0/" in value for value in ipv4_changes))

    def test_network_setup_rejects_obsolete_mtu_mode_argument(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443", "--auto-mtu=false", success=False)
        self.assertFalse((self.root / "commands.jsonl").exists())

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

    def test_down_reports_failed_network_inventory(self):
        for failure in ("fail_nft_list", "fail_ip_list"):
            with self.subTest(failure=failure):
                self.update_state(
                    nft_tables={"ip porta": "old", "inet porta_guard": "old guard"},
                    **({"fail_nft_list": False, "fail_ip_list": False} | {failure: True}),
                )
                result = self.run_script("server-down.sh", "porta0", success=False)
                self.assertIn("could not", result.stderr)

    def test_up_rejects_failed_nft_inventory_before_changing_network(self):
        old_tables = {"ip porta": "old", "inet porta_guard": "old guard"}
        self.update_state(nft_tables=old_tables, fail_nft_list=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443", success=False)
        self.assertEqual(self.state()["nft_tables"], old_tables)
        self.assertFalse(any(call[0] in ("ip", "sysctl") for call in self.commands()))

    def test_docker_inventory_failure_preserves_recovery_marker(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.update_state(fail_iptables_list=True)
        self.run_script("server-down.sh", "porta0", success=False)
        self.assertEqual((self.root / "runtime/docker-rules-porta0").read_text(), "eth0\n")
        self.assertEqual(len(self.state()["iptables_rules"]), 2)

    def test_down_retires_docker_marker_when_chain_is_confirmed_absent(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443")
        self.update_state(docker=False, iptables_rules=[])
        self.run_script("server-down.sh", "porta0")
        self.assertFalse((self.root / "runtime/docker-rules-porta0").exists())

    def test_invalid_docker_marker_is_retained_without_using_invalid_interfaces(self):
        directory = self.root / "runtime"
        directory.mkdir()
        marker = directory / "docker-rules-porta0"
        marker.write_text("invalid interface\n")
        self.update_state(docker=True)
        self.run_script("server-down.sh", "porta0", success=False)
        self.assertTrue(marker.exists())
        self.assertFalse(any("invalid interface" in call for call in self.commands()))

    def test_native_firewall_runner_isolates_runtime_files(self):
        sentinel = self.root / "runtime"
        sentinel.mkdir()
        marker = sentinel / "ip-forward-porta0"
        marker.write_text("sentinel\n")
        self.run_script("test-server-firewall.sh")
        self.assertEqual(marker.read_text(), "sentinel\n")
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

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

    def test_version_advances_above_global_tags_and_allows_release_reruns(self):
        self.update_state(previous_version="0.1.29",
                          release_tags=["v0.1.27", "v0.1.38", "v0.1.099"])
        self.version_file("0.1.30")
        self.run_script("check-version.sh", "base", success=False)
        self.version_file("0.1.39")
        self.run_script("check-version.sh", "base")
        self.update_state(release_tags=["v0.1.38", "v0.1.39"])
        self.run_script("check-version.sh", "base", success=False)
        self.update_state(tag_commits={"v0.1.39": "b" * 40})
        self.run_script("check-version.sh", "base")
        self.version_file("0.1.40")
        self.update_state(previous_version="0.1.39")
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
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 8443;", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE", unit)
        self.assertEqual(self.state()["stopped_helpers"][0], "old down")
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_deploy_automatic_mtu_preserves_custom_ceiling(self):
        deploy = self.prepare_deploy(timer=False)
        self.run_deploy(deploy, "--build-local", "--auto-mtu", "--mtu", "1280")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--auto-mtu=true", unit)
        self.assertIn("--mtu 1280", unit)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443;", unit)

    def test_deploy_fixed_mtu_disables_discovery_but_preserves_feedback_setup(self):
        deploy = self.prepare_deploy(timer=False)
        self.run_deploy(deploy, "--build-local", "--auto-mtu=false", "--mtu", "1100")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--auto-mtu=false", unit)
        self.assertNotIn("--auto-mtu=true", unit)
        self.assertIn("--mtu 1100", unit)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443;", unit)

    def test_bundled_service_uses_automatic_mtu_defaults(self):
        unit = (ROOT / "deploy/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        setup = next(line for line in unit.splitlines() if line.startswith("ExecStartPost="))
        self.assertIn("--auto-mtu=true", start)
        self.assertIn("--mtu 1400", unit)
        self.assertIn("--landing-template-dir /etc/porta/landing", start)
        self.assertNotIn("--auto-mtu", setup)
        self.assertIn("eth0 8443;", setup)
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

    def test_deployed_certificate_sync_follows_renewal_symlinks(self):
        deploy = self.prepare_deploy()
        old_cert, old_key = self.certificate_pair("archive-old", "old")
        renewed_cert, renewed_key = self.certificate_pair("archive-renewed", "renewed")
        cert_link, key_link = self.root / "live.crt", self.root / "live.key"
        cert_link.symlink_to(old_cert)
        key_link.symlink_to(old_key)
        self.run_deploy(deploy, "--build-local", "--cert", cert_link, "--key", key_link)
        cert_link.unlink()
        key_link.unlink()
        cert_link.symlink_to(renewed_cert)
        key_link.symlink_to(renewed_key)
        result = subprocess.run(
            [str(self.bin / "systemctl"), "start", "porta-cert-sync.service"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        destination = self.root / "system/etc/porta/tls"
        self.assertEqual((destination / "server.crt").read_text(), "certificate:renewed")
        self.assertEqual((destination / "server.key").read_text(), "key:renewed")

    def test_static_tls_probe_verifies_the_installed_certificate(self):
        deploy = self.prepare_deploy()
        cert, key = self.certificate_pair("source", "new")
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key)
        probe = next(call for call in self.commands()
                     if call[0] == "curl" and "--resolve" in call)
        self.assertNotIn("--insecure", probe)
        self.assertEqual(probe[probe.index("--cacert") + 1],
                         str(self.root / "system/etc/porta/tls/server.crt"))
        self.assertEqual(probe[probe.index("--noproxy") + 1], "*")

    def test_static_tls_probe_accepts_private_cert_and_rejects_wrong_peer(self):
        real_openssl = shutil.which("openssl")
        real_curl = shutil.which("curl")
        self.assertIsNotNone(real_openssl)
        self.assertIsNotNone(real_curl)
        (self.bin / "openssl").unlink()
        (self.bin / "openssl").symlink_to(real_openssl)
        certificate, key = self.root / "source.crt", self.root / "source.key"
        subprocess.run(
            [real_openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-sha256", "-days", "1",
             "-subj", "/CN=vpn.example", "-addext", "subjectAltName=DNS:vpn.example",
             "-keyout", str(key), "-out", str(certificate)],
            check=True, capture_output=True, timeout=10,
        )
        deploy = self.prepare_deploy()
        self.run_deploy(deploy, "--build-local", "--cert", certificate, "--key", key)
        probe = next(call for call in self.commands()
                     if call[0] == "curl" and "--resolve" in call)

        class LandingHandler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()

            def log_message(self, *args):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), LandingHandler) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                port = server.server_port
                for host, expected_status in (("vpn.example", 0), ("wrong.example", 60)):
                    with self.subTest(host=host):
                        command = [real_curl, *probe[1:]]
                        command[command.index("--resolve") + 1] = f"{host}:{port}:127.0.0.1"
                        command[-1] = f"https://{host}:{port}/"
                        result = subprocess.run(
                            command, env=self.env | {
                                "HTTPS_PROXY": "http://127.0.0.1:1",
                                "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "",
                            }, capture_output=True, text=True, timeout=10,
                        )
                        self.assertEqual(result.returncode, expected_status, result.stderr)
                        if expected_status == 0:
                            self.assertEqual(result.stdout, "200|text/html")
            finally:
                server.shutdown()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())

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
        (release / "SHA256SUMS.sig").write_bytes(b"manifest signature")
        (release / "release-signing-cert.der").write_bytes(b"signer certificate")
        assets.extend(["SHA256SUMS", "SHA256SUMS.sig", "release-signing-cert.der"])
        (release / "release.json").write_text(json.dumps({
            "tag_name": "v0.1.4",
            "assets": [{"name": name, "url":
                        f"https://api.github.com/repos/huangyingting/porta/releases/assets/{index}"}
                       for index, name in enumerate(assets, start=1)],
        }))

    def test_release_upgrade_publishes_complete_download_set(self):
        deploy = self.prepare_deploy()
        self.release_assets()
        self.run_deploy(deploy)
        downloads = self.root / "system/var/lib/porta/downloads"
        self.assertEqual((downloads / "CLIENT_VERSION").read_text(), "v0.1.4\n")
        self.assertTrue((downloads / "porta-client-windows-amd64.zip").is_file())
        self.assertTrue((downloads / "SHA256SUMS.sig").is_file())
        self.assertTrue((downloads / "release-signing-cert.der").is_file())
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
        for call in curl_calls:
            if any("api.github.com" in arg for arg in call):
                self.assertIn("@", "".join(call))
                self.assertIn("--proto-redir", call)
                self.assertNotIn("--location-trusted", call)
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_release_rejects_untrusted_asset_urls_before_sending_credentials(self):
        deploy = self.prepare_deploy()
        self.release_assets()
        self.env["GH_TOKEN"] = "secret-test-token"
        metadata_path = self.root / "release/release.json"
        metadata = json.loads(metadata_path.read_text())
        for url in ("https://evil.example/asset", "http://api.github.com/asset",
                    "https://api.github.com@evil.example/asset",
                    "https://api.github.com/repos/other/repo/releases/assets/1"):
            with self.subTest(url=url):
                metadata["assets"][0]["url"] = url
                metadata_path.write_text(json.dumps(metadata))
                self.run_deploy(deploy, success=False)
                self.assertNotIn("stopped_helpers", self.state())
        calls = [call for call in self.commands() if call[0] == "curl"]
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(any(arg.endswith("/releases/latest") for arg in call)
                            for call in calls))

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

    def test_release_signature_and_certificate_fail_before_mutation(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets()
        for state in ({"fail_release_signature": True},
                      {"fail_release_signature": False, "release_fingerprint": "0" * 64}):
            with self.subTest(state=state):
                self.update_state(**state)
                self.run_deploy(deploy, success=False)
                self.assertEqual(self.snapshot(), before)
                self.assertNotIn("stopped_helpers", self.state())
                self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def release_script(self, name):
        return self.workflow_script("release.yml", name)

    def workflow_script(self, filename, name):
        workflow = (ROOT / ".github/workflows" / filename).read_text()
        step = workflow.split(f"      - name: {name}\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        script = step.split("        run: ", 1)[1]
        if script.startswith("|\n"):
            return "\n".join(line[10:] for line in script[2:].splitlines())
        return script.strip()

    def test_branch_and_pr_ci_has_an_unconditional_required_gate(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn('  push:\n    branches:\n      - "**"', triggers)
        self.assertIn("  pull_request:\n    branches:\n      - main", triggers)
        self.assertNotIn("tags:", triggers)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("schedule:", triggers)
        self.assertIn("name: CI required\n    if: ${{ always() }}", workflow)
        self.assertIn("needs: [go, windows-ui, android]", workflow)
        script = self.workflow_script("ci.yml", "Require every build and test job")
        success = {"GO_RESULT": "success", "WINDOWS_RESULT": "success",
                   "ANDROID_RESULT": "success"}
        cases = [(success, True)]
        for job in success:
            for outcome in ("failure", "cancelled", "skipped"):
                cases.append((success | {job: outcome}, False))
        for results, accepted in cases:
            with self.subTest(results=results):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    cwd=self.root, env=self.env | results,
                    text=True, capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted,
                                 result.stdout + result.stderr)

    def test_release_only_builds_the_successful_trusted_main_push(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("workflow_run:", triggers)
        self.assertIn("workflows: [CI]", triggers)
        self.assertIn("types: [completed]", triggers)
        self.assertIn("branches: [main]", triggers)
        self.assertNotIn("workflow_dispatch:", triggers)
        self.assertNotIn("push:", triggers)
        for guard in (
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.head_branch == 'main'",
            "github.event.workflow_run.head_repository.full_name == github.repository",
        ):
            self.assertEqual(workflow.count(guard), 2)
        self.assertEqual(workflow.count("ref: ${{ github.event.workflow_run.head_sha }}"), 2)
        self.assertIn("group: release-main\n  cancel-in-progress: false", workflow)
        self.assertLess(workflow.index("- name: Verify release version"),
                        workflow.index("- name: Prepare persistent Android signing key"))

    def test_release_version_checks_real_commit_ancestry_and_tag_identity(self):
        repository = self.root / "repository"
        git = shutil.which("git")
        environment = self.env | {"PATH": os.environ["PATH"],
                                  "GITHUB_ENV": str(self.root / "github.env")}

        def run_git(*args):
            result = subprocess.run([git, "-C", str(repository), *args],
                                    env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout.strip()

        repository.mkdir()
        run_git("init", "--quiet", "--initial-branch=main")
        run_git("config", "user.name", "Workflow Test")
        run_git("config", "user.email", "workflow-test@example.invalid")
        run_git("commit", "--quiet", "--allow-empty", "-m", "base")
        base = run_git("rev-parse", "HEAD")
        run_git("commit", "--quiet", "--allow-empty", "-m", "tested main")
        head = run_git("rev-parse", "HEAD")
        run_git("update-ref", "refs/remotes/origin/main", head)
        (repository / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/check-version.sh", repository / "scripts/check-version.sh")
        version = repository / "internal/buildinfo/VERSION"
        version.parent.mkdir(parents=True)
        version.write_text("0.1.39\n")

        def verify(sha, accepted):
            output = self.root / "github.env"
            output.unlink(missing_ok=True)
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", self.release_script("Verify release version")],
                cwd=repository, env=environment | {"PORTA_RELEASE_SHA": sha},
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode == 0, accepted,
                             result.stdout + result.stderr)
            if accepted:
                self.assertIn("PORTA_RELEASE_TAG=v0.1.39\n", output.read_text())
                self.assertIn("PORTA_ANDROID_VERSION_CODE=1039\n", output.read_text())
            else:
                self.assertFalse(output.exists())

        verify(head, True)
        verify(base, False)
        run_git("update-ref", "refs/remotes/origin/main", base)
        verify(head, False)
        run_git("update-ref", "refs/remotes/origin/main", head)
        run_git("tag", "-a", "v0.1.39", "-m", "matching release", head)
        verify(head, True)
        run_git("tag", "-d", "v0.1.39")
        run_git("tag", "v0.1.39", base)
        verify(head, False)

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

    def test_android_workflows_do_not_request_removed_sdk_tools(self):
        for filename in ("ci.yml", "release.yml", "live.yml"):
            workflow = (ROOT / ".github/workflows" / filename).read_text()
            self.assertRegex(
                workflow,
                r"uses: android-actions/setup-android@[0-9a-f]{40}[^\n]*\n"
                r"        with:\n          packages: platform-tools\n",
                filename,
            )

    def signing_environment(self):
        return self.env | {
            "RUNNER_TEMP": str(self.root / "scratch"),
            "GITHUB_ENV": str(self.root / "github.env"),
            "KEYSTORE_BASE64": base64.b64encode(b"signing-fixture").decode(),
            "KEYSTORE_PASSWORD": "test-only",
            "KEY_ALIAS": "porta",
            "KEY_PASSWORD": "test-only",
        }

    def test_release_manifest_pin_and_publication_contract(self):
        pin = (ROOT / "android/signing-certificate.sha256").read_text().strip()
        self.assertRegex(pin, r"^[0-9a-f]{64}$")
        deploy = (ROOT / "scripts/deploy.sh").read_text()
        self.assertIn("release_signing_fingerprint=" + pin, deploy)
        self.assertLess(deploy.index("openssl dgst -sha256"),
                        deploy.index('actual_checksum=$(sha256sum'))
        signing = self.release_script("Sign release manifest")
        self.assertIn("java scripts/SignReleaseManifest.java", signing)
        self.assertIn("android/signing-certificate.sha256", signing)
        publishing = self.release_script("Publish GitHub release")
        for artifact in ("SHA256SUMS", "SHA256SUMS.sig", "release-signing-cert.der"):
            self.assertIn("dist/" + artifact, signing)
            self.assertIn("dist/" + artifact, publishing)

    def test_release_manifest_real_signatures_and_tamper_rejection(self):
        tools = {name: shutil.which(name) for name in ("java", "keytool", "openssl")}
        if not all(tools.values()):
            self.skipTest("Java 17, keytool and OpenSSL are required for signing integration")
        environment = self.env | {
            "PATH": os.environ["PATH"],
            "PORTA_ANDROID_KEYSTORE_PASSWORD": "test-password",
            "PORTA_ANDROID_KEY_PASSWORD": "test-password",
            "PORTA_ANDROID_KEY_ALIAS": "porta",
        }

        def run(*arguments, success=True):
            result = subprocess.run(
                arguments, cwd=self.root, env=environment, text=True,
                capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            return result.stdout

        manifest = self.root / "SHA256SUMS"
        manifest.write_text("fixture release manifest\n")
        for algorithm in ("EC", "RSA"):
            with self.subTest(algorithm=algorithm):
                store = self.root / (algorithm + ".p12")
                certificate = self.root / (algorithm + ".der")
                signature = self.root / (algorithm + ".sig")
                public_key = self.root / (algorithm + ".pem")
                run(tools["keytool"], "-J-Djava.io.tmpdir=" + str(self.root / "scratch"),
                    "-genkeypair", "-noprompt", "-keystore", str(store),
                    "-storetype", "PKCS12", "-storepass", "test-password",
                    "-keypass", "test-password", "-alias", "porta",
                    "-dname", "CN=Porta Test", "-keyalg", algorithm, "-validity", "1")
                run(tools["keytool"], "-exportcert", "-keystore", str(store),
                    "-storepass", "test-password", "-alias", "porta",
                    "-file", str(certificate))
                fingerprint = hashlib.sha256(certificate.read_bytes()).hexdigest()
                signer = (
                    tools["java"], "-Djava.io.tmpdir=" + str(self.root / "scratch"),
                    str(ROOT / "scripts/SignReleaseManifest.java"), str(store),
                    str(manifest), str(signature), str(certificate),
                )
                run(*signer, "0" * 64, success=False)
                self.assertFalse(signature.exists())
                manifest.write_text("fixture release manifest\n")
                run(*signer, fingerprint)
                public_key.write_text(run(tools["openssl"], "x509", "-inform", "DER",
                                          "-in", str(certificate), "-pubkey", "-noout"))
                verify = (
                    tools["openssl"], "dgst", "-sha256", "-verify", str(public_key),
                    "-signature", str(signature), str(manifest),
                )
                run(*verify)
                manifest.write_text("tampered manifest\n")
                run(*verify, success=False)

    def test_live_ci_is_credential_free_and_full_vpn_is_protected(self):
        workflow = (ROOT / ".github/workflows/live.yml").read_text()
        live = workflow[workflow.index("  live-windows:"):]
        self.assertNotIn("secrets.", live)
        self.assertIn('cron: "23 3 * * *"', workflow)
        self.assertIn("PORTA_TLS_TEST_URL: https://porta-dev.i-csu.org:8443", live)
        self.assertIn("TestLivePlatformTLSAndAuthentication", live)
        self.assertIn("connectedDebugAndroidTest", live)
        self.assertIn("CertificateVerificationTest", live)
        self.assertIn("portaTlsOrigin=https://porta-dev.i-csu.org:8443", live)
        vpn = workflow.split("  vpn-e2e-linux:\n", 1)[1].split("  live-windows:\n", 1)[0]
        self.assertIn("environment: development", vpn)
        self.assertIn("group: porta-development-vpn-e2e", vpn)
        self.assertIn("cancel-in-progress: false", vpn)
        self.assertIn("secrets.PORTA_E2E_TOKEN", vpn)
        self.assertIn("secrets.PORTA_E2E_LINUX_IDENTITY_BASE64", vpn)
        self.assertNotIn("secrets.", vpn.split("- name: Exercise", 1)[0])
        self.assertIn("inputs.vpn_e2e && 'vpn-e2e'", workflow)
        self.assertEqual(workflow.count("github.ref == 'refs/heads/main'"), 3)

    def test_native_windows_packaging_and_static_go_release_contract(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn('PORTA_WFP_NATIVE_TEST: "1"', ci)
        self.assertIn("PORTA_WFP_NATIVE_TEST_MARKER", ci)
        self.assertIn("native WFP rollback acceptance did not run", ci)
        self.assertRegex(release, r"(?ms)^  windows:\n.*?runs-on: windows-latest")
        self.assertIn("needs: windows", release)
        self.assertIn("name: porta-windows-release", release)
        self.assertIn("actions/download-artifact@", release)
        for workflow in (ci, release):
            self.assertIn("scripts/package-windows.go", workflow)
            self.assertRegex(workflow, r"go test -count=1[^\n]+ ./internal/device ")
            self.assertIn("node --test cmd/porta-windows/frontend_test.cjs", workflow)
            self.assertIn("go-version-file: go.mod", workflow)
            self.assertIn("golang.org/x/mobile/cmd/gomobile@", workflow)
            self.assertIn("go build -tags production", workflow)
            self.assertNotRegex(workflow, r"\b(cargo|rustup)\b")
        self.assertIn("CGO_ENABLED=0 GOOS=linux", release)
        self.assertIn("is not a static Go binary", release)
        self.assertNotIn("GLIBC_", release)
        checksum = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
        for content in (ci, release, (ROOT / "Makefile").read_text()):
            self.assertIn(checksum, content.lower())

    def test_native_client_networking_isolated_from_host_network_and_resolver(self):
        harness = (ROOT / "scripts/test-client-network.sh").read_text()
        helper = (ROOT / "scripts/native-client-network/main_linux.go").read_text()
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("sudo -n unshare --net --mount --propagation private --", harness)
        self.assertIn('mount --bind "$runtime_directory/etc" /etc', harness)
        self.assertIn('mount --bind "$runtime_directory/run" /run', harness)
        self.assertIn('CGO_ENABLED=0 "${GO:-go}" build', harness)
        self.assertIn("PORTA_NATIVE_CLIENT_NETWORK_TEST=1", harness)
        self.assertIn('"PORTA_NATIVE_CLIENT_NETWORK_TEST"', helper)
        self.assertIn('os.Readlink("/proc/self/ns/net")', helper)
        self.assertIn('os.Readlink("/proc/1/ns/net")', helper)
        self.assertIn("current == host", helper)
        self.assertIn("network.Prepare(ctx, endpoint)", helper)
        self.assertIn("network.Up(ctx, tun.Name(), endpoint, lease)", helper)
        self.assertIn("network.Down(ctx)", helper)
        self.assertIn("./scripts/test-client-network.sh", makefile)
        self.assertNotIn("cargo", harness)

    def test_full_vpn_harness_uses_real_go_client_and_checks_cleanup(self):
        harness = (ROOT / "scripts/test-live-vpn.sh").read_text()
        for fragment in (
            'CGO_ENABLED=0 "$go" build', "./cmd/porta-client",
            "ip netns add", "type veth", "masquerade",
            'ip daddr "$gateway" drop', '--identity "$identity_path"',
            '--transport "$transport"', '--network-state "$state_path"',
            "connected address=.* transport=$transport",
            "ip -4 route show proto 186", 'ip -4 route get "$gateway"',
            "ping -n -c 3", 'ping -n -c 1 -W 5 -M do -s "$df_payload"',
            "Porta-owned routes remain", "Porta leak-protection table remains",
            "private Porta gateway remains reachable",
            'install -o "$(id -u)" -g "$(id -g)" -m 0600',
            "PORTA_E2E_ARTIFACT_DIR must not already exist",
            'kill -KILL "$client_pid"',
        ):
            self.assertIn(fragment, harness)
        self.assertNotIn("--token", harness)
        self.assertNotIn("cargo", harness)
        self.assertNotIn("mktemp", harness)

    def test_full_vpn_invalid_configuration_never_runs_network_commands(self):
        self.env.update(PORTA_E2E_TOKEN="", PORTA_E2E_LINUX_IDENTITY_BASE64="")
        cases = (
            {"PORTA_E2E_SERVER": "http://vpn.example"},
            {"PORTA_E2E_SERVER": "https://user:password@vpn.example"},
            {"PORTA_E2E_GATEWAY": "bad"},
            {"PORTA_E2E_SERVER_ADDRESS": "::1"},
            {"PORTA_E2E_TRANSPORTS": "h3 invalid"},
            {},
            {"PORTA_E2E_TOKEN": "test-token-at-least-16"},
        )
        for values in cases:
            with self.subTest(values=values):
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/test-live-vpn.sh")],
                    cwd=self.root, env=self.env | values, text=True,
                    capture_output=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "commands.jsonl").exists())

    def test_browser_layout_reports_startup_failure_without_hanging(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is required for browser harness tests")
        chrome = self.root / "failing-chrome"
        chrome.write_text("#!/bin/sh\necho fixture-chrome-failure >&2\nexit 7\n")
        chrome.chmod(0o755)
        for binary, message in ((chrome, "fixture-chrome-failure"),
                                (self.root / "missing-chrome", "Chrome failed to start")):
            with self.subTest(binary=binary):
                result = subprocess.run(
                    [node, str(ROOT / "scripts/tests/onboarding_layout.cjs")],
                    cwd=self.root, env=self.env | {"CHROME_BIN": str(binary)},
                    text=True, capture_output=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_full_vpn_namespace_checks_routes_packets_and_cleanup(self):
        work = self.root / "vpn-work"
        work.mkdir()
        (work / "client-token").write_text("fixture-token-not-a-real-credential")
        (work / "client-identity.json").write_text("{}")
        interface = self.root / "sys/class/net/porta-ci0"
        interface.mkdir(parents=True)
        (interface / "mtu").write_text("1400\n")
        harness = self.root / "vpn-harness.sh"
        harness.write_text((ROOT / "scripts/test-live-vpn.sh").read_text()
                           .replace("/sys/class/net/", str(self.root / "sys/class/net") + "/")
                           .replace("$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                    "$fake_bin:$PATH"))
        harness.chmod(0o755)
        stub = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import sys
import time
work = Path(os.environ["VPN_WORK"])
program = Path(sys.argv[0]).name
args = sys.argv[1:]
active = work / "active"
state = work / "network-state.json"
with (work / "calls.jsonl").open("a") as log:
    log.write(json.dumps([program, *args]) + "\\n")
if program == "client":
    if "--token" in args or os.environ.get("PORTA_TOKEN") != "fixture-token-not-a-real-credential":
        raise SystemExit("client automation must provide tokens only through PORTA_TOKEN")
    if "--cleanup-network" in args:
        state.unlink(missing_ok=True)
        raise SystemExit(0)
    def stop(*_):
        active.unlink(missing_ok=True)
        if os.environ.get("VPN_STALE_STATE") != "1":
            state.unlink(missing_ok=True)
        raise SystemExit(0)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    active.touch()
    state.write_text("{}")
    transport = args[args.index("--transport") + 1]
    print("connected address=10.66.0.2/24 transport=" + transport + " uploaded=0", flush=True)
    while True:
        time.sleep(0.01)
elif program == "ip":
    if args[:4] == ["link", "show", "dev", "porta-ci0"]:
        raise SystemExit(0 if active.exists() else 1)
    if args[:3] == ["-4", "route", "get"]:
        print("10.66.0.1 dev porta-ci0")
    elif args[:3] == ["-4", "route", "show"]:
        if active.exists():
            print("0.0.0.0/1 dev porta-ci0 proto 186\\n128.0.0.0/1 dev porta-ci0 proto 186")
    else:
        raise SystemExit("unexpected mock ip command")
elif program == "nft" and args == ["list", "tables"]:
    if active.exists():
        print("table inet porta_fixture")
elif program == "ping":
    raise SystemExit(0 if active.exists() else 1)
else:
    raise SystemExit("unexpected mock command")
"""
        client = self.root / "client"
        client.write_text(stub)
        client.chmod(0o755)
        for name in ("ip", "nft", "ping"):
            command = self.bin / name
            command.unlink(missing_ok=True)
            command.write_text(stub)
            command.chmod(0o755)
        (self.bin / "sleep").unlink()
        for stale in ("0", "1"):
            with self.subTest(stale=stale):
                result = subprocess.run(
                    ["bash", str(harness), "--namespace", str(ROOT), str(work),
                     "https://vpn.example", "10.66.0.1", "h3 h2", str(client)],
                    cwd=self.root, env=self.env | {"VPN_WORK": str(work),
                                                 "VPN_STALE_STATE": stale},
                    text=True, capture_output=True, timeout=20,
                )
                self.assertEqual(result.returncode == 0, stale == "0",
                                 result.stdout + result.stderr)
                self.assertFalse((work / "active").exists())
                self.assertFalse((work / "network-state.json").exists(), result.stderr)
                if stale == "1":
                    self.assertIn("network recovery state remains", result.stderr)
        calls = [json.loads(line) for line in (work / "calls.jsonl").read_text().splitlines()]
        connections = [call for call in calls if call[0] == "client" and "--transport" in call]
        self.assertEqual([call[call.index("--transport") + 1] for call in connections],
                         ["h3", "h2", "h3"])
        self.assertTrue(all("--identity" in call and "--reconnect=false" in call
                            for call in connections))
        self.assertTrue(any("--cleanup-network" in call for call in calls))
        self.assertTrue(any(call[0] == "ping" and "-M" in call for call in calls))
        self.assertNotIn("fixture-token-not-a-real-credential", json.dumps(calls))

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
            env=self.env | {"GITHUB_REF_NAME": "main", "PORTA_RELEASE_TAG": "v0.1.4",
                            "PORTA_RELEASE_SHA": "a" * 40},
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
        self.assertIn(["git", "tag", "v0.1.4", "a" * 40], self.commands())
        self.assertIn(["git", "push", "origin", "refs/tags/v0.1.4"], self.commands())

    def test_published_release_is_not_overwritten_on_rerun(self):
        self.update_state(release_draft=False)
        self.publish_release(success=False)
        self.assertEqual(len(self.commands()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
