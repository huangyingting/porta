#!/usr/bin/env python3
"""Run shell regressions without invoking host service or networking commands."""

import base64
import hashlib
import fcntl
import http.server
import json
import os
import pathlib
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import threading
import time
import unittest
import uuid
import xml.etree.ElementTree as ET


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
            "PORTA_BACKUP_ALLOW_NONROOT": "1",
        }
        self.write_state(
            sysctl={
                "net.core.rmem_max": "212992",
                "net.core.wmem_max": "212992",
                "net.ipv4.ip_forward": "0",
            }
        )
        for command in (
            "mktemp", "systemctl", "sysctl", "ip", "nft", "iptables", "ip6tables", "openssl",
            "curl", "ss", "make", "mv", "git", "adb", "sleep", "gh", "uname",
            "sudo", "unshare", "getent", "useradd", "groupadd", "usermod", "chown", "chgrp", "systemd-tmpfiles",
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
                                      "check-version.sh", "build-android-rust.sh",
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

    def test_certificate_group_grants_the_service_user_read_access(self):
        cert, key = self.certificate_pair("source", "one")
        destination = self.root / "tls"
        self.run_script("sync-cert.sh", cert, key, destination)
        # An unchanged pair still gains group access when a group is added.
        self.run_script("sync-cert.sh", cert, key, destination, "porta")
        self.assertEqual((destination / "server.key").stat().st_mode & 0o777, 0o640)
        self.assertEqual((destination / "server.crt").stat().st_mode & 0o777, 0o644)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o750)
        self.assertIn(["chgrp", "porta", str(destination / "server.key")],
                      self.state()["ownership"])
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
        self.assertIn('set tcp4 { type ipv4_addr; size 65535; flags dynamic,timeout; }', transaction)
        self.assertIn('update @tcp4 { ip saddr timeout 10s limit rate over 200/second', transaction)
        self.assertIn('update @udp6 { ip6 saddr timeout 10s limit rate over 500/second', transaction)
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

    def test_relay_forwards_clients_only_through_the_upstream_tunnel(self):
        self.update_state(docker=True)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                        "eth0", "8443", "--upstream-interface", "porta-up0")
        transaction = self.state()["nft_transaction"]
        self.assertIn('iifname "porta0" oifname "porta-up0" accept', transaction)
        self.assertIn('iifname "porta-up0" oifname "porta0" ct state established,related accept',
                      transaction)
        self.assertIn('oifname "porta-up0" ip saddr 10.66.0.0/24 masquerade', transaction)
        self.assertNotIn('oifname "eth0"', transaction)
        self.assertIn("tcp option maxseg size set rt mtu", transaction)
        self.assertIn('iifname "porta-up0" drop', transaction)
        # The public input guard still protects the physical interface.
        self.assertIn('iifname "eth0" meta nfproto ipv4 tcp dport 8443', transaction)
        state = self.state()
        self.assertEqual(state["ip_rules"], ["10066:\tfrom all iif porta0 lookup 10066"])
        self.assertEqual(state["ip_routes"]["10066"], [
            "default dev porta-up0",
            "unreachable default metric 4294967295",
            "throw 10.66.0.0/24",
        ])
        self.assertEqual(state["sysctl"]["net.ipv4.conf.porta-up0.rp_filter"], "2")
        self.assertTrue(all("porta-up0" in " ".join(rule) for rule in state["iptables_rules"]))
        self.assertEqual((self.root / "runtime/docker-rules-porta0").read_text(), "porta-up0\n")

    def test_relay_routing_is_idempotent_and_removed_on_down_or_exit_mode(self):
        relay = ("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        self.run_script(*relay, "--upstream-interface", "porta-up0")
        self.run_script(*relay, "--upstream-interface", "porta-up0")
        self.assertEqual(len(self.state()["ip_rules"]), 1)
        self.run_script("server-down.sh", "porta0", "eth0")
        self.assertEqual(self.state()["ip_rules"], [])
        self.assertNotIn("10066", self.state()["ip_routes"])

        self.run_script(*relay, "--upstream-interface", "porta-up0")
        self.run_script(*relay)
        self.assertEqual(self.state()["ip_rules"], [])
        self.assertNotIn("10066", self.state()["ip_routes"])
        self.assertIn('oifname "eth0" ip saddr 10.66.0.0/24 masquerade',
                      self.state()["nft_transaction"])

    def test_named_and_local_exits_get_tables_forwarding_and_cleanup(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443",
                        "--upstream-interface", "porta-up0", "--exit-interface", "porta-up1",
                        "--local-exit")
        state = self.state()
        transaction = state["nft_transaction"]
        forward = transaction.split("chain forward {", 1)[1].split("}", 1)[0]
        rules = [line.strip() for line in forward.splitlines()
                 if line.strip() and "type filter" not in line and not line.strip().startswith("#")]
        # The default egress stays first for readiness.
        self.assertEqual(rules[:6], [
            'iifname "porta0" oifname "porta-up0" accept',
            'iifname "porta-up0" oifname "porta0" ct state established,related accept',
            'iifname "porta0" oifname "porta-up1" accept',
            'iifname "porta-up1" oifname "porta0" ct state established,related accept',
            'iifname "porta0" oifname "eth0" accept',
            'iifname "eth0" oifname "porta0" ct state established,related accept',
        ])
        for interface in ("porta-up0", "porta-up1", "eth0"):
            self.assertIn(f'oifname "{interface}" ip saddr 10.66.0.0/24 masquerade', transaction)
        self.assertIn('iifname "porta-up1" drop', transaction.split("chain relay_input {", 1)[1])
        self.assertEqual(state["ip_routes"]["10067"],
                         ["default dev porta-up1", "unreachable default metric 4294967295"])
        self.assertEqual(state["sysctl"]["net.ipv4.conf.porta-up1.rp_filter"], "2")

        # A stopped daemon's per-lease exit rules are removed with the tables.
        self.update_state(ip_rules=self.state()["ip_rules"] + [
            "10065:\tfrom 10.66.0.5 iif porta0 lookup 10067",
            "10065:\tfrom 10.66.0.6 iif porta0 lookup main",
        ])
        self.run_script("server-down.sh", "porta0", "eth0")
        state = self.state()
        self.assertEqual(state["ip_rules"], [])
        self.assertNotIn("10067", state["ip_routes"])

        for options in (["--local-exit"], ["--exit-interface", "porta0"],
                        ["--exit-interface", "porta-up1", "--exit-interface", "porta-up1"]):
            with self.subTest(options=options):
                self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                                "eth0", "8443", *options, success=False)

    def test_relay_rejects_reused_interfaces_before_mutation(self):
        for options in (["--upstream-interface", "porta0"], ["--upstream-interface", "eth0"],
                        ["--upstream-interface", "bad/name"], ["--upstream-interface"],
                        ["porta-up0"], ["--unknown"]):
            with self.subTest(options=options):
                self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                                "eth0", "8443", *options, success=False)
        self.assertFalse((self.root / "commands.jsonl").exists())

    def test_clients_cannot_reach_metadata_or_host_services_by_default(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        transaction = self.state()["nft_transaction"]
        self.assertIn('iifname "porta0" ip daddr { 169.254.0.0/16, 100.100.100.200 } drop',
                      transaction)
        guard = transaction.split("chain client_input {", 1)[1].split("\n  }", 1)[0]
        self.assertIn('iifname "porta0" ct state established,related accept', guard)
        self.assertIn("th dport 53 accept", guard)
        self.assertTrue(guard.rstrip().endswith('iifname "porta0" drop'))
        self.assertIn('iifname != { "lo", "porta0" } ip daddr 10.66.0.1 drop', transaction)

        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443",
                        "--client-host-access")
        transaction = self.state()["nft_transaction"]
        self.assertNotIn("chain client_input", transaction)
        # Instance metadata stays blocked even when host access is allowed.
        self.assertIn("169.254.0.0/16", transaction)

    def test_kernel_never_forwards_between_clients(self):
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        transaction = self.state()["nft_transaction"]
        forward = transaction.split("chain forward {", 1)[1].split("}", 1)[0].splitlines()
        rules = [line.strip() for line in forward
                 if line.strip() and "type filter" not in line and not line.strip().startswith("#")]
        # Readiness requires the egress and return rules to stay first; the
        # daemon switches client-to-client traffic itself.
        self.assertEqual(rules, [
            'iifname "porta0" oifname "eth0" accept',
            'iifname "eth0" oifname "porta0" ct state established,related accept',
            'iifname "porta0" drop',
            'oifname "porta0" drop',
        ])
        # The option moved to the daemon.
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443",
                        "--client-to-client", success=False)

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

    def test_server_up_forwards_and_guards_ipv6_and_server_down_restores_it(self):
        sysctl = self.state()["sysctl"] | {
            "net.ipv6.conf.all.forwarding": "0",
            "net.ipv6.conf.eth0.accept_ra": "1",
        }
        self.update_state(sysctl=sysctl, docker=True, docker6=True)
        dual = ("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443",
                "--ipv6", "fd66::1/64", "fd66::/64")
        result = self.run_script(*dual)
        self.assertIn("masqueraded through eth0", result.stdout)
        state = self.state()
        self.assertEqual(state["sysctl"]["net.ipv6.conf.all.forwarding"], "1")
        self.assertEqual(state["sysctl"]["net.ipv6.conf.eth0.accept_ra"], "2")
        self.assertEqual(state["sysctl"]["net.ipv6.conf.porta0.disable_ipv6"], "0")
        self.assertIn(["ip", "-6", "address", "replace", "fd66::1/64", "dev", "porta0", "nodad"],
                      self.commands())
        transaction = state["nft_transaction"]
        self.assertIn("table ip6 porta {", transaction)
        self.assertIn('iifname "porta0" oifname "eth0" accept', transaction)
        self.assertIn('oifname "eth0" ip6 saddr fd66::/64 masquerade', transaction)
        self.assertIn("fd00:ec2::254", transaction)
        self.assertIn('iifname != { "lo", "porta0" } ip6 daddr fd66::1 drop', transaction)
        self.assertIn("packet-too-big", transaction)
        self.assertEqual(len(state["ip6tables_rules"]), 2)
        self.assertEqual(len(state["iptables_rules"]), 2)

        # Restarting keeps the saved originals; routed prefixes skip NAT.
        self.run_script(*dual, "--ipv6-routed")
        state = self.state()
        self.assertNotIn("ip6 saddr fd66::/64 masquerade", state["nft_transaction"])
        self.assertEqual(len(state["ip6tables_rules"]), 2)

        self.run_script("server-down.sh", "porta0", "eth0")
        state = self.state()
        self.assertEqual(state["sysctl"]["net.ipv6.conf.all.forwarding"], "0")
        self.assertEqual(state["sysctl"]["net.ipv6.conf.eth0.accept_ra"], "1")
        self.assertNotIn("ip6 porta", state["nft_tables"])
        self.assertEqual(state["ip6tables_rules"], [])
        self.assertFalse(any((self.root / "runtime").glob("*6*")))

        # Without --ipv6 a later start removes the IPv6 table and rules.
        self.run_script(*dual)
        self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24", "eth0", "8443")
        state = self.state()
        self.assertNotIn("ip6 porta", state["nft_tables"])
        self.assertEqual(state["ip6tables_rules"], [])

    def test_server_up_rejects_ipv6_on_a_cascade_relay(self):
        result = self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                                 "eth0", "8443", "--upstream-interface", "porta-up0",
                                 "--ipv6", "fd66::1/64", "fd66::/64", success=False)
        self.assertIn("not supported with --upstream-interface", result.stderr)
        result = self.run_script("server-up.sh", "porta0", "10.66.0.1/24", "10.66.0.0/24",
                                 "eth0", "8443", "--ipv6", "10.0.0.1/24", "fd66::/64",
                                 success=False)
        self.assertIn("invalid IPv6", result.stderr)

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

    def test_rust_package_versions_match_application_version(self):
        version = (ROOT / "internal/buildinfo/VERSION").read_text().strip()
        for manifest in (ROOT / "rust").glob("*/Cargo.toml"):
            package = manifest.read_text().split("[package]", 1)
            if len(package) != 2:
                continue
            match = re.search(r'(?m)^version = "([^"]+)"$', package[1])
            self.assertIsNotNone(match, manifest)
            self.assertEqual(match.group(1), version, manifest)

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

    def prepare_android_rust_build(self):
        ndk = self.root / "ndk"
        tools = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        tools.mkdir(parents=True)
        for name in (
            "aarch64-linux-android26-clang",
            "armv7a-linux-androideabi26-clang",
            "x86_64-linux-android26-clang",
        ):
            (tools / name).write_text("#!/bin/sh\n")
            (tools / name).chmod(0o755)
        readelf = tools / "llvm-readelf"
        readelf.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'LOAD 0 0 0 0 0 R E 0x4000'\n"
        )
        readelf.chmod(0o755)

        rustup = self.root / "rustup"
        rustup.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' aarch64-linux-android armv7-linux-androideabi "
            "x86_64-linux-android\n"
        )
        rustup.chmod(0o755)
        cargo = self.root / "cargo"
        cargo.write_text(
            "#!/bin/sh\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = --target ]; then target=$2; shift 2; else shift; fi\n"
            "done\n"
            "mkdir -p \"$CARGO_TARGET_DIR/$target/release\"\n"
            "printf '%s' \"$target\" > "
            "\"$CARGO_TARGET_DIR/$target/release/libporta_android.so\"\n"
        )
        cargo.chmod(0o755)
        target_dir = self.root / "target"
        self.env.update(
            ANDROID_NDK_ROOT=str(ndk),
            ANDROID_NDK_HOME=str(ndk),
            CARGO=str(cargo),
            RUSTUP=str(rustup),
            CARGO_TARGET_DIR=str(target_dir),
        )
        return readelf

    def test_android_rust_libraries_use_requested_output_directory(self):
        self.prepare_android_rust_build()
        self.run_script("build-android-rust.sh", "nested/jni")
        expected = {
            "arm64-v8a": "aarch64-linux-android",
            "armeabi-v7a": "armv7-linux-androideabi",
            "x86_64": "x86_64-linux-android",
        }
        for abi, target in expected.items():
            self.assertEqual((self.root / f"nested/jni/{abi}/libporta_android.so").read_text(),
                             target)

    def test_android_rust_build_rejects_failed_or_invalid_elf_inspection(self):
        readelf = self.prepare_android_rust_build()
        cases = {
            "inspection-failed": (
                "printf '%s\\n' 'LOAD 0 0 0 0 0 R E 0x4000'\nexit 1\n"
            ),
            "empty": "exit 0\n",
            "no-load-headers": "printf '%s\\n' 'Program Headers:'\n",
            "malformed": "printf '%s\\n' 'LOAD 0 0 0 0 0 R E invalid'\n",
            "misaligned": "printf '%s\\n' 'LOAD 0 0 0 0 0 R E 0x1000'\n",
            "mixed-alignment": (
                "printf '%s\\n' 'LOAD 0 0 0 0 0 R E 0x4000' "
                "'LOAD 0 0 0 0 0 R E 0x1000'\n"
            ),
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                readelf.write_text("#!/bin/sh\n" + body)
                self.run_script("build-android-rust.sh", f"jni-{name}", success=False)

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
            "/usr/local/bin", "/usr/local/sbin", "/usr/local/libexec/porta", "/etc/porta",
            "/etc/sysctl.d", "/etc/tmpfiles.d", "/etc/systemd/system", "/var/lib/porta",
            "/var/backups/porta", "/run/lock",
        ):
            source = source.replace(prefix, str(self.root / "system" / prefix[1:]))
        source = source.replace("[[ $EUID -eq 0 ]]", "true")
        deploy = checkout / "scripts/deploy.sh"
        deploy.write_text(source)
        for directory in (
            "usr/local/bin", "usr/local/libexec/porta", "etc/porta/tls",
            "etc/porta/landing", "etc/sysctl.d", "etc/tmpfiles.d", "etc/systemd/system",
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

    def test_deploy_relay_routes_through_upstream_and_keeps_its_token(self):
        deploy = self.prepare_deploy(timer=False)
        token = "relay-account-token-0123456789"
        self.env["PORTA_UPSTREAM_TOKEN"] = token
        result = self.run_deploy(deploy, "--build-local",
                                 "--upstream", "https://exit.example:8443/")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--upstream https://exit.example:8443 --upstream-interface porta-up0 "
                      f"--upstream-identity {self.root}/system/var/lib/porta/upstream-identity.json",
                      unit)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443 "
                      "--upstream-interface porta-up0;", unit)
        self.assertNotIn(token, unit)
        self.assertNotIn(token, result.stdout + result.stderr)
        environment = self.root / "system/etc/porta/porta.env"
        self.assertIn(f"PORTA_UPSTREAM_TOKEN={token}\n", environment.read_text())
        self.assertIn("PORTA_TOKEN=old-client\n", environment.read_text())
        self.assertEqual(environment.stat().st_mode & 0o777, 0o600)
        self.assertIn("relayed through https://exit.example:8443", result.stdout)

        # Upgrades reuse the saved next-hop token.
        del self.env["PORTA_UPSTREAM_TOKEN"]
        self.run_deploy(deploy, "--build-local", "--upstream", "https://exit.example:8443")
        self.assertEqual(environment.read_text().count("PORTA_UPSTREAM_TOKEN="), 1)
        self.assertIn(f"PORTA_UPSTREAM_TOKEN={token}\n", environment.read_text())

    def test_deploy_named_exits_get_tokens_interfaces_and_local_exit(self):
        deploy = self.prepare_deploy(timer=False)
        self.env["PORTA_UPSTREAM_TOKEN"] = "relay-account-token-0123456789"
        self.env["PORTA_EXIT_TOKEN_US_WEST"] = "us-west-account-token-0123456789"
        result = self.run_deploy(deploy, "--build-local", "--upstream", "https://eu.example",
                                 "--exits", "us-west=https://us.example:8443", "--local-exit")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        self.assertIn("--exit us-west=https://us.example:8443 --local-exit", start)
        self.assertIn("--upstream-interface porta-up0 --exit-interface porta-up1 --local-exit;",
                      unit)
        environment = (self.root / "system/etc/porta/porta.env").read_text()
        self.assertIn("PORTA_EXIT_TOKEN_US_WEST=us-west-account-token-0123456789\n", environment)
        self.assertNotIn("us-west-account-token", unit + result.stdout + result.stderr)
        self.assertIn("Selectable exits: local, us-west", result.stdout)
        config = (self.root / "system/etc/porta/deploy.conf").read_text()
        self.assertIn("exits=us-west=https://us.example:8443\n", config)

        # Upgrades reuse the saved exit token; --exits= removes exits and tokens.
        del self.env["PORTA_EXIT_TOKEN_US_WEST"]
        self.run_deploy(deploy, "--build-local")
        self.assertIn("PORTA_EXIT_TOKEN_US_WEST=",
                      (self.root / "system/etc/porta/porta.env").read_text())
        self.run_deploy(deploy, "--build-local", "--exits=", "--local-exit=false")
        self.assertNotIn("PORTA_EXIT_TOKEN_", (self.root / "system/etc/porta/porta.env").read_text())
        self.assertNotIn("--exit", (self.root / "system/etc/systemd/system/porta.service").read_text())

        for options in (("--exits", "us=https://us.example"),
                        ("--exits", "local=https://us.example"),
                        ("--exits", "us=http://us.example"),
                        ("--no-upstream", "--local-exit")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)

    def test_deploy_dns_resolver_installs_blocklist_and_binds_port_53(self):
        deploy = self.prepare_deploy(timer=False)
        cert, key = self.certificate_pair("source", "new")
        blocklist = self.root / "blocklist.txt"
        blocklist.write_text("ads.example\n")
        result = self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key,
                                 "--port", "8443", "--dns-resolver",
                                 "--dns-upstreams", "9.9.9.9,149.112.112.112:53",
                                 "--dns-forwards", "corp.example=10.20.0.53",
                                 "--dns-blocklist", blocklist)
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        installed = self.root / "system/etc/porta/dns-blocklist.txt"
        self.assertIn("--dns-resolver --dns-upstream 9.9.9.9 --dns-upstream 149.112.112.112:53 "
                      f"--dns-forward corp.example=10.20.0.53 --dns-blocklist {installed}", start)
        # Port 53 needs the bind capability even with a high public port.
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n", unit)
        self.assertEqual(installed.read_text(), "ads.example\n")
        self.assertIn("built-in resolver on 10.66.0.1", result.stdout)

        self.run_deploy(deploy, "--build-local", "--dns-resolver=false", "--dns-upstreams=",
                        "--dns-forwards=", "--dns-blocklist=")
        self.assertFalse(installed.exists())
        self.assertNotIn("--dns-resolver",
                         (self.root / "system/etc/systemd/system/porta.service").read_text())
        for options in (("--dns-upstreams", "9.9.9.9"), ("--dns-resolver", "--dns-upstreams", "bad"),
                        ("--dns-resolver", "--dns-blocklist", "/missing")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)

    def test_deploy_oidc_derives_the_redirect_and_keeps_the_secret_private(self):
        deploy = self.prepare_deploy(timer=False)
        self.env["PORTA_OIDC_CLIENT_SECRET"] = "oidc-client-secret-0123456789"
        result = self.run_deploy(deploy, "--build-local", "--port", "8443",
                                 "--oidc-issuer", "https://login.example.com/tenant/v2.0",
                                 "--oidc-client-id", "porta-admin")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--oidc-issuer https://login.example.com/tenant/v2.0 --oidc-client-id porta-admin "
                      "--oidc-redirect-url https://vpn.example:8443/auth/oidc/callback", unit)
        environment = self.root / "system/etc/porta/porta.env"
        self.assertIn("PORTA_OIDC_CLIENT_SECRET=oidc-client-secret-0123456789\n", environment.read_text())
        self.assertNotIn("oidc-client-secret", unit + result.stdout + result.stderr)
        self.assertIn("User sign-in:    access tokens from an administrator", result.stdout)
        result = self.run_deploy(deploy, "--build-local", "--sso-user-domains", "example.org,corp.example",
                                 "--sso-max-devices", "3")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("/auth/oidc/callback --sso-user-domains example.org,corp.example --sso-max-devices 3", unit)
        self.assertIn("User sign-in:    single sign-on for example.org, corp.example (up to 3 devices each)",
                      result.stdout)
        for options in (("--sso-user-domains", "not a domain"), ("--sso-max-devices", "0"),
                        ("--sso-max-devices", "101"), ("--sso-max-devices", "08")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)
        self.run_deploy(deploy, "--build-local", "--sso-user-domains=")
        self.assertNotIn("--sso-user-domains", (self.root / "system/etc/systemd/system/porta.service").read_text())
        del self.env["PORTA_OIDC_CLIENT_SECRET"]
        self.run_deploy(deploy, "--build-local")
        self.assertIn("PORTA_OIDC_CLIENT_SECRET=", environment.read_text())
        self.run_deploy(deploy, "--build-local", "--oidc-issuer=", "--oidc-client-id=")
        self.assertNotIn("PORTA_OIDC_CLIENT_SECRET", environment.read_text())
        self.assertNotIn("--oidc", (self.root / "system/etc/systemd/system/porta.service").read_text())
        for options in (("--oidc-issuer", "http://login.example.com"), ("--oidc-issuer", "https://login.example.com")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)

    def test_deploy_federation_saves_the_token_and_points_replicas_at_the_primary(self):
        deploy = self.prepare_deploy(timer=False)
        token = "federation-token-0123456789abcdefghij"
        self.env["PORTA_FEDERATION_TOKEN"] = token
        result = self.run_deploy(deploy, "--build-local", "--federation-primary", "https://primary.example/")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--federation-primary https://primary.example --mtu", unit)
        environment = self.root / "system/etc/porta/porta.env"
        self.assertIn(f"PORTA_FEDERATION_TOKEN={token}\n", environment.read_text())
        self.assertNotIn(token, unit + result.stdout + result.stderr)
        self.assertIn("mirrored from https://primary.example", result.stdout)
        del self.env["PORTA_FEDERATION_TOKEN"]
        # The primary keeps serving replicas with the saved token.
        self.run_deploy(deploy, "--build-local", "--federation-primary=")
        self.assertIn("PORTA_FEDERATION_TOKEN=", environment.read_text())
        self.assertNotIn("--federation-primary", (self.root / "system/etc/systemd/system/porta.service").read_text())
        self.run_deploy(deploy, "--build-local", "--disable-federation")
        self.assertNotIn("PORTA_FEDERATION_TOKEN", environment.read_text())
        self.env["PORTA_FEDERATION_TOKEN"] = "short"
        self.run_deploy(deploy, "--build-local", success=False)
        del self.env["PORTA_FEDERATION_TOKEN"]
        self.run_deploy(deploy, "--build-local", "--federation-primary", "https://primary.example", success=False)

    def test_deploy_client_to_client_is_passed_to_the_daemon(self):
        deploy = self.prepare_deploy(timer=False)
        result = self.run_deploy(deploy, "--build-local", "--client-to-client")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        self.assertIn("--dns 1.1.1.1 --client-to-client --mtu", start)
        self.assertIn("server-up.sh porta0 10.66.0.1/24 10.66.0.0/24 eth0 443;", unit)
        self.assertIn("allowed within 10.66.0.0/24", result.stdout)
        self.assertIn("Direct paths:    off", result.stdout)

        # Saved like other options, so a plain redeploy keeps direct paths.
        self.run_deploy(deploy, "--build-local", "--peer-to-peer")
        result = self.run_deploy(deploy, "--build-local")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        self.assertIn("--dns 1.1.1.1 --client-to-client --peer-to-peer --mtu", start)
        self.assertIn("Direct paths:    offered", result.stdout)
        self.run_deploy(deploy, "--build-local", "--peer-to-peer=false")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertNotIn("--peer-to-peer", unit)

        result = self.run_deploy(deploy, "--build-local", "--min-client-version", "0.1.40")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("--min-client-version 0.1.40", unit)
        self.assertIn("Client versions: 0.1.40 or newer", result.stdout)
        self.run_deploy(deploy, "--build-local", "--min-client-version", "latest", success=False)
        self.run_deploy(deploy, "--build-local", "--min-client-version=")
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertNotIn("--min-client-version", unit)

    def test_deploy_backs_up_before_upgrading_and_installs_daily_backups(self):
        deploy = self.prepare_deploy(timer=False)
        result = self.run_deploy(deploy, "--build-local")
        system = self.root / "system"
        archives = sorted((system / "var/backups/porta").glob("porta-*.tar.gz"))
        self.assertEqual(len(archives), 1, result.stdout)
        self.assertIn(f"backed up the current gateway to {archives[0]}", result.stdout)
        listing = subprocess.run(["tar", "-tzf", str(archives[0])], text=True,
                                 capture_output=True, check=True).stdout
        self.assertIn("state/clients.json", listing)
        self.assertIn("config/porta.env", listing)
        restored = subprocess.run(["tar", "-xOzf", str(archives[0]), "state/clients.json"],
                                  capture_output=True, check=True).stdout
        self.assertEqual(restored, b'{"old":"client"}')
        self.assertTrue((system / "usr/local/sbin/porta-backup").stat().st_mode & 0o111)
        for unit in ("porta-backup.service", "porta-backup.timer"):
            self.assertTrue((system / "etc/systemd/system" / unit).is_file())
        self.assertIn("porta-backup.timer", self.state()["enabled"])
        self.assertIn("Backups:         daily to", result.stdout)

        # A fresh installation has nothing to back up.
        shutil.rmtree(self.root / "system")
        shutil.rmtree(self.root / "checkout")
        fresh = self.prepare_deploy(existing=False, timer=False)
        self.run_deploy(fresh, "--build-local")
        self.assertEqual(list((self.root / "system/var/backups/porta").glob("*.tar.gz")), [])

    def test_deploy_runs_the_daemon_as_an_unprivileged_user(self):
        deploy = self.prepare_deploy(timer=False)
        cert, key = self.certificate_pair("source", "new")
        self.run_deploy(deploy, "--build-local", "--cert", cert, "--key", key)
        unit = (self.root / "system/etc/systemd/system/porta.service").read_text()
        self.assertIn("\nUser=porta\nGroup=porta\n", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n", unit)
        self.assertNotIn("RuntimeDirectory", unit)
        self.assertIn("ReadWritePaths=/run/porta\n", unit)
        tmpfiles = self.root / "system/etc/tmpfiles.d/porta.conf"
        self.assertIn("d /run/porta 0700 root root -", tmpfiles.read_text())
        self.assertIn(["systemd-tmpfiles", "--create", str(tmpfiles)], self.commands())
        # Network helpers keep root but not the daemon's other privileges.
        self.assertIn("ExecStartPost=!/bin/bash -c", unit)
        self.assertIn("ExecStopPost=!", unit)
        self.assertIn("test -r " + str(self.root / "system/etc/porta/tls/server.key"), unit)
        sync = (self.root / "system/etc/systemd/system/porta-cert-sync.service").read_text()
        self.assertIn(str(self.root / "system/etc/porta/tls") + " porta\n", sync)
        self.assertEqual(self.state()["users"], ["porta"])
        ownership = self.state()["ownership"]
        self.assertIn(["chown", "porta:porta", str(self.root / "system/var/lib/porta")], ownership)
        self.assertTrue(any(call[:2] == ["chgrp", "porta"] and call[2].endswith("/server.key")
                            for call in ownership), ownership)
        tls = self.root / "system/etc/porta/tls"
        self.assertEqual((tls / "server.key").stat().st_mode & 0o777, 0o640)
        self.assertEqual(tls.stat().st_mode & 0o777, 0o750)

        # Redeploying keeps the existing user.
        self.run_deploy(deploy, "--build-local")
        self.assertEqual(self.state()["users"], ["porta"])

    def test_release_bundle_contains_every_deploy_file_the_script_installs(self):
        import re
        used = set(re.findall(r"\bdeploy/[A-Za-z0-9_.-]+", (ROOT / "scripts/deploy.sh").read_text()))
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        package = workflow.split("name: Package deployment tools", 1)[1].split("- name:", 1)[0]
        self.assertTrue(used)
        for path in used:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
                self.assertIn(path, package)

    def test_bundled_units_run_the_daemon_unprivileged(self):
        unit = (ROOT / "deploy/porta.service").read_text()
        self.assertIn("\nUser=porta\nGroup=porta\n", unit)
        self.assertIn("ExecStartPost=!/bin/bash", unit)
        self.assertIn("ExecStopPost=!/usr/local/libexec/porta/server-down.sh", unit)
        sync = (ROOT / "deploy/porta-cert-sync.service").read_text()
        self.assertIn("/etc/porta/tls porta\n", sync)
        self.assertIn("CAP_CHOWN", sync)

    def test_deploy_split_tunnel_routes_are_passed_saved_and_cleared(self):
        deploy = self.prepare_deploy(timer=False)
        result = self.run_deploy(deploy, "--build-local", "--routes", "10.20.0.0/16,192.168.5.0/24",
                                 "--dns-domains", "corp.example")
        unit_path = self.root / "system/etc/systemd/system/porta.service"
        unit = unit_path.read_text()
        self.assertIn("--dns 1.1.1.1 --route 10.20.0.0/16 --route 192.168.5.0/24 "
                      "--dns-domain corp.example --mtu", unit)
        self.assertIn("split tunnel: 10.20.0.0/16, 192.168.5.0/24 (DNS for corp.example)",
                      result.stdout)
        config = (self.root / "system/etc/porta/deploy.conf").read_text()
        self.assertIn("routes=10.20.0.0/16,192.168.5.0/24\n", config)

        result = self.run_deploy(deploy, "--build-local", "--routes=", "--dns-domains=")
        self.assertNotIn("--route", unit_path.read_text())
        self.assertIn("Client routing:  full tunnel", result.stdout)
        for options in (("--routes", "10.20.0.0/16;reboot"), ("--routes", "corp"),
                        ("--dns-domains", "corp.example"),
                        ("--routes", "10.20.0.0/16", "--dns-domains", "bad_domain")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)

    def test_deploy_ipv6_pool_is_generated_passed_saved_and_cleared(self):
        deploy = self.prepare_deploy(timer=False)
        result = self.run_deploy(deploy, "--build-local", "--ipv6",
                                 "--routes", "10.20.0.0/16,2001:db8::/32")
        unit_path = self.root / "system/etc/systemd/system/porta.service"
        unit = unit_path.read_text()
        match = re.search(r"--ipv6-pool (fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}::/64) ", unit)
        self.assertIsNotNone(match, unit)
        prefix = match.group(1)
        gateway = prefix.replace("::/64", "::1/64")
        self.assertIn(f"--ipv6 {gateway} {prefix};", unit)
        self.assertIn("--route 2001:db8::/32", unit)
        self.assertIn(f"Client IPv6:     {prefix}, masqueraded through eth0", result.stdout)
        config_path = self.root / "system/etc/porta/deploy.conf"
        self.assertIn(f"ipv6_pool={prefix}\n", config_path.read_text())

        # Upgrades keep the generated prefix; a routed prefix skips NAT.
        self.run_deploy(deploy, "--build-local", "--ipv6")
        self.assertIn(f"--ipv6-pool {prefix} ", unit_path.read_text())
        self.run_deploy(deploy, "--build-local", "--ipv6-pool", "2001:db8:66::/64",
                        "--ipv6-routed", "--routes=")
        unit = unit_path.read_text()
        self.assertIn("--ipv6 2001:db8:66::1/64 2001:db8:66::/64 --ipv6-routed;", unit)

        result = self.run_deploy(deploy, "--build-local", "--no-ipv6")
        self.assertNotIn("ipv6", unit_path.read_text())
        self.assertIn("Client IPv6:     off", result.stdout)
        for options in (("--ipv6-pool", "fd66::/121"), ("--ipv6-pool", "10.0.0.0/8"),
                        ("--routes", "2001:db8::/32"), ("--ipv6-routed",),
                        ("--ipv6", "--mtu", "1200")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)

    def test_linux_desktop_installer_sets_up_service_group_and_menu_entry(self):
        checkout = self.root / "checkout"
        shutil.copytree(ROOT / "scripts", checkout / "scripts")
        shutil.copytree(ROOT / "deploy", checkout / "deploy")
        script = checkout / "scripts/install-linux-desktop.sh"
        source = script.read_text().replace("[[ $EUID -eq 0 ]]", "true")
        for prefix in ("/usr/local/bin", "/etc/systemd/system", "/usr/share"):
            source = source.replace(prefix, str(self.root / "system" / prefix[1:]))
        script.write_text(source)
        for directory in ("usr/local/bin", "etc/systemd/system"):
            (self.root / "system" / directory).mkdir(parents=True, exist_ok=True)
        binaries = checkout / "bin"
        binaries.mkdir()
        for name in ("porta-client", "porta-desktop"):
            (binaries / name).write_text("#!/bin/sh\n")
            (binaries / name).chmod(0o755)

        result = subprocess.run(["bash", str(script), "--user", "root"], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("added root", result.stdout)
        system = self.root / "system"
        unit = (system / "etc/systemd/system/porta-client.service").read_text()
        self.assertIn("--daemon --control-group porta-client", unit)
        self.assertIn("RuntimeDirectory=porta-client", unit)
        self.assertTrue((system / "usr/local/bin/porta-desktop").exists())
        entry = (system / "usr/share/applications/porta-desktop.desktop").read_text()
        self.assertIn("Exec=porta-desktop", entry)
        self.assertTrue((system / "usr/share/icons/hicolor/256x256/apps/porta.png").exists())
        state = self.state()
        self.assertEqual(state["groups"], ["porta-client"])
        self.assertEqual(state["members"], [["porta-client", "root"]])
        self.assertTrue(state["active"]["porta-client.service"])
        self.assertEqual(state["enabled"]["porta-client.service"], "enabled")

        # Reinstalling keeps the existing group.
        result = subprocess.run(["bash", str(script), "--user", "root"], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state()["groups"], ["porta-client"])
        for options in (["--user", "no such user"], ["--client", str(checkout / "missing")]):
            result = subprocess.run(["bash", str(script), *options], cwd=self.root,
                                    env=self.env, text=True, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0, options)

    def test_deploy_relay_without_token_fails_before_stopping_service(self):
        deploy = self.prepare_deploy(timer=False)
        before = self.snapshot()
        result = self.run_deploy(deploy, "--build-local", "--upstream",
                                 "https://exit.example", success=False)
        self.assertIn("PORTA_UPSTREAM_TOKEN", result.stderr)
        self.assertTrue(self.state()["active"]["porta.service"])
        self.assertEqual(self.snapshot(), before)
        for options in (("--upstream", "http://exit.example"),
                        ("--upstream", "https://vpn.example"),
                        ("--upstream-ca", "/etc/ssl/ca.pem")):
            with self.subTest(options=options):
                self.run_deploy(deploy, "--build-local", *options, success=False)
        self.assertTrue(self.state()["active"]["porta.service"])

    def test_deploy_upgrade_without_options_reuses_saved_configuration(self):
        deploy = self.prepare_deploy(timer=False)
        self.env["PORTA_UPSTREAM_TOKEN"] = "relay-account-token-0123456789"
        self.run_deploy(deploy, "--build-local", "--port", "8443", "--dns", "9.9.9.9",
                        "--upstream", "https://exit.example", "--client-to-client")
        del self.env["PORTA_UPSTREAM_TOKEN"]
        unit_path = self.root / "system/etc/systemd/system/porta.service"
        first = unit_path.read_text()
        config = self.root / "system/etc/porta/deploy.conf"
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertIn("upstream=https://exit.example\n", config.read_text())
        self.assertIn("external_interface=eth0\n", config.read_text())

        result = subprocess.run(["bash", str(deploy), "--build-local"], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("deploy: changing", result.stdout)
        self.assertEqual(unit_path.read_text(), first)
        # Nothing but the binary changed: the gateway restarts in place.
        self.assertIn("ExecReload=/bin/kill -HUP $MAINPID\n", first)
        self.assertIn("restarting the running gateway in place", result.stdout)
        self.assertEqual(self.state()["reloaded"], ["porta.service"])

        # Explicit options override and are saved; off-switches clear values.
        result = self.run_deploy(deploy, "--build-local", "--no-upstream",
                                 "--client-to-client=false", "--dns", "1.0.0.1")
        self.assertIn("deploy: changing upstream: https://exit.example -> (unset)", result.stdout)
        self.assertNotIn("in place", result.stdout)
        self.assertEqual(self.state()["reloaded"], ["porta.service"])
        self.assertIn("deploy: changing dns: 9.9.9.9 -> 1.0.0.1", result.stdout)
        unit = unit_path.read_text()
        self.assertNotIn("--upstream", unit)
        self.assertNotIn("--client-to-client", unit)
        self.assertIn("--listen :8443", unit)
        self.assertIn("upstream=\n", config.read_text())

    def test_deploy_rejects_invalid_saved_configuration_before_stopping_service(self):
        deploy = self.prepare_deploy(timer=False)
        config = self.root / "system/etc/porta/deploy.conf"
        for contents, message in (("dns=1.1.1.1; reboot\n", "invalid line 1"),
                                  ("unknown_option=1\n", "unknown option 'unknown_option'"),
                                  ("client_to_client=yes\n", "invalid saved value"),
                                  ("port=$(id)\n", "invalid line 1")):
            with self.subTest(contents=contents):
                config.write_text(contents)
                before = self.snapshot()
                result = self.run_deploy(deploy, "--build-local", success=False)
                self.assertIn(message, result.stderr)
                self.assertTrue(self.state()["active"]["porta.service"])
                self.assertEqual(self.snapshot(), before)

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
        self.assertNotIn("--upstream", unit)
        start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        setup = next(line for line in unit.splitlines() if line.startswith("ExecStartPost="))
        self.assertIn("--auto-mtu=true", start)
        self.assertIn("--mtu 1400", unit)
        self.assertIn("--landing-template-dir /etc/porta/landing", start)
        self.assertNotIn("--auto-mtu", setup)
        self.assertIn("eth0 8443;", setup)
        # Helper journals live in a root-only directory that outlives restarts.
        self.assertIn("ReadWritePaths=/run/porta\n", unit)
        self.assertNotIn("RuntimeDirectory", unit)
        tmpfiles = (ROOT / "deploy/porta-tmpfiles.conf").read_text()
        self.assertIn("d /run/porta 0700 root root -", tmpfiles)

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

    def release_assets(self, landing_templates=True, proxy_headers=True, desktop=False):
        release = self.root / "release"
        release.mkdir()
        assets = [
            "porta-server-linux-amd64", "porta-client-linux-amd64",
            "porta-client-linux-arm64", "porta-client-windows-amd64.zip",
            "porta-android-arm64-v8a.apk", "porta-android-armeabi-v7a.apk",
            "porta-android-x86_64.apk",
        ] + (["porta-desktop-linux-amd64.tar.gz"] if desktop else [])
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
        (release / "SHA256SUMS.sig").write_bytes(b"signed manifest")
        (release / "release-signing-cert.der").write_bytes(b"release certificate")
        assets.extend(["SHA256SUMS", "SHA256SUMS.sig", "release-signing-cert.der"])
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
        self.assertTrue((downloads / "SHA256SUMS.sig").is_file())
        self.assertTrue((downloads / "release-signing-cert.der").is_file())
        self.assertFalse((downloads / "old-client").exists())
        self.assertEqual(list((self.root / "scratch").iterdir()), [])

    def test_releases_with_the_desktop_package_serve_it_and_others_do_not_need_it(self):
        deploy = self.prepare_deploy()
        self.release_assets(desktop=True)
        result = self.run_deploy(deploy)
        downloads = self.root / "system/var/lib/porta/downloads"
        self.assertEqual((downloads / "porta-desktop-linux-amd64.tar.gz").read_text(),
                         "porta-desktop-linux-amd64.tar.gz")
        self.assertIn("Linux app:   https://vpn.example/download/porta-desktop-linux-amd64.tar.gz",
                      result.stdout)
        self.assertNotIn("\n\n  Linux ARM64", result.stdout)

        shutil.rmtree(self.root / "release")
        self.release_assets()
        result = self.run_deploy(deploy)
        self.assertFalse((downloads / "porta-desktop-linux-amd64.tar.gz").exists())
        self.assertNotIn("Linux app:", result.stdout)
        self.assertIn("  Linux AMD64: https://vpn.example/download/porta-client-linux-amd64\n"
                      "  Linux ARM64:", result.stdout)

        shutil.rmtree(self.root / "release")
        self.release_assets(desktop=True)
        (self.root / "release/porta-desktop-linux-amd64.tar.gz").write_text("corrupt")
        before = self.snapshot()
        self.run_deploy(deploy, success=False)
        self.assertEqual(self.snapshot(), before)

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

    def test_release_signature_failure_leaves_installation_untouched(self):
        deploy = self.prepare_deploy()
        before = self.snapshot()
        self.release_assets()
        self.update_state(fail_release_signature=True)
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
        return self.workflow_script("release.yml", name)

    def workflow_script(self, filename, name):
        workflow = (ROOT / ".github/workflows" / filename).read_text()
        step = workflow.split(f"      - name: {name}\n", 1)[1]
        step = step.split("\n      - ", 1)[0]
        script = step.split("        run: ", 1)[1]
        if script.startswith("|\n"):
            return "\n".join(line[10:] for line in script[2:].splitlines())
        return script.strip()

    def test_main_requires_rust_promotion_and_all_platform_results(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn('  push:\n    branches:\n      - "**"', triggers)
        self.assertIn("  pull_request:\n    branches:\n      - main", triggers)
        self.assertNotIn("tags:", triggers)
        self.assertNotIn("schedule:", triggers)
        self.assertNotIn("secrets.", workflow)
        self.assertIn("name: ${{ github.event_name == 'pull_request' && 'Rust PR required' || 'Rust CI required' }}\n"
                      "    if: ${{ always() }}", workflow)
        self.assertIn("needs: [rust, dependencies, fuzz, masque-interop, apple, windows, android]", workflow)
        script = self.workflow_script("ci.yml", "Require Rust promotion and every build")
        good = {
            "EVENT_NAME": "pull_request", "HEAD_BRANCH": "rust",
            "HEAD_REPOSITORY": "huangyingting/porta", "REPOSITORY": "huangyingting/porta",
            "RUST_RESULT": "success", "WINDOWS_RESULT": "success", "ANDROID_RESULT": "success",
            "INTEROP_RESULT": "success", "APPLE_RESULT": "success",
            "DEPENDENCIES_RESULT": "success", "FUZZ_RESULT": "success",
        }
        cases = [(good, True), (good | {"EVENT_NAME": "push", "HEAD_BRANCH": ""}, True)]
        for job in ("RUST_RESULT", "WINDOWS_RESULT", "ANDROID_RESULT", "INTEROP_RESULT", "APPLE_RESULT", "DEPENDENCIES_RESULT", "FUZZ_RESULT"):
            for outcome in ("failure", "cancelled", "skipped"):
                cases.append((good | {job: outcome}, False))
        cases.extend([
            (good | {"HEAD_BRANCH": "golang"}, False),
            (good | {"HEAD_BRANCH": "feature"}, False),
            (good | {"HEAD_REPOSITORY": "other/porta"}, False),
        ])
        for values, accepted in cases:
            with self.subTest(values=values):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    cwd=self.root, env=self.env | values,
                    text=True, capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted,
                                 result.stdout + result.stderr)

    def test_release_only_builds_the_successful_trusted_main_push(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        for value in ("workflow_run:", "workflows: [CI]", "types: [completed]", "branches: [main]"):
            self.assertIn(value, triggers)
        self.assertNotIn("push:", triggers)
        self.assertNotIn("workflow_dispatch:", triggers)
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

    def deployment_bundle_script(self, path):
        blocks = re.findall(
            r"```(?:bash|sh)\n(.*?)\n```",
            (ROOT / path).read_text(),
            flags=re.DOTALL,
        )
        matches = [
            block for block in blocks
            if "porta-deploy.tar.gz" in block
            and "release-signing-cert.der" in block
            and "tar -xzf" in block
        ]
        self.assertEqual(len(matches), 1, path)
        return matches[0]

    def write_mock_command(self, name, script):
        command = self.bin / name
        command.unlink(missing_ok=True)
        command.write_text("#!/bin/sh\nset -eu\n" + script)
        command.chmod(0o755)

    def test_backups_round_trip_verify_prune_and_restore_with_an_undo_copy(self):
        root = self.root / "backup"
        config, state, archives, tools = (root / name for name in ("etc", "state", "archives", "bin"))
        for directory in (config / "tls", state / "acme", state / "downloads", tools):
            directory.mkdir(parents=True)
        (config / "porta.env").write_text("PORTA_ADMIN_TOKEN=secret\n")
        (config / "tls/server.key").write_text("key")
        for name, text in {"clients.json": "clients-v1", "leases.json": "leases-v1",
                           "usage.json": "{}", "admins.json": "[]", "sso-users.json": "{}", "audit.log": "line\n",
                           "audit.log.1": "older\n", "acme/cert": "acme",
                           "downloads/porta-client": "binary", "clients.json.lock": ""}.items():
            (state / name).write_text(text)
        log = root / "systemctl.log"
        (tools / "systemctl").write_text(f"#!/bin/sh\necho \"$*\" >> {log}\n")
        (tools / "curl").write_text("#!/bin/sh\nexit 0\n")
        for tool in ("systemctl", "curl"):
            (tools / tool).chmod(0o755)
        env = {**os.environ, "PATH": f"{tools}:/usr/bin:/bin", "PORTA_BACKUP_ALLOW_NONROOT": "1",
               "PORTA_CONFIG_DIR": str(config), "PORTA_STATE_DIR": str(state),
               "PORTA_BACKUP_DIR": str(archives), "PORTA_READY_URL": "http://127.0.0.1:1/readyz",
               "TMPDIR": str(self.root / "scratch")}

        def backup(*args, success=True):
            result = subprocess.run(["bash", str(ROOT / "scripts/porta-backup.sh"), *args],
                                    env=env, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            return result

        first = pathlib.Path(backup("create").stdout.strip())
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        listing = subprocess.run(["tar", "-tzf", str(first)], text=True, capture_output=True).stdout
        for member in ("config/porta.env", "config/tls/server.key", "state/clients.json",
                       "state/sso-users.json", "state/audit.log.1", "state/acme/cert", "MANIFEST", "SHA256SUMS"):
            self.assertIn(member, listing)
        self.assertNotIn("downloads", listing)
        self.assertNotIn("clients.json.lock", listing)
        self.assertIn("files verified", backup("verify", first).stdout)

        # Archives are named by second; retention keeps the newest.
        import time as clock
        for _ in range(2):
            clock.sleep(1.1)
            backup("create", "--keep", "2")
        self.assertEqual(len(backup("list").stdout.split()), 2)
        self.assertFalse(first.exists())
        newest = pathlib.Path(backup("list").stdout.split()[0])

        tampered = archives / "porta-tampered.tar.gz"
        work = self.root / "scratch/tamper"
        work.mkdir()
        subprocess.run(["tar", "-C", str(work), "-xzf", str(newest)], check=True)
        (work / "state/clients.json").write_text("forged")
        subprocess.run(["tar", "-C", str(work), "-czf", str(tampered), "."], check=True)
        self.assertIn("checksums", backup("verify", tampered, success=False).stderr)
        self.assertIn("no archive",
                      backup("verify", archives / "missing.tar.gz", success=False).stderr)
        foreign = archives / "foreign.tar.gz"
        subprocess.run(["tar", "-C", str(config), "-czf", str(foreign), "porta.env"], check=True)
        self.assertIn("not a Porta backup", backup("verify", foreign, success=False).stderr)
        foreign.unlink()
        tampered.unlink()

        (state / "clients.json").write_text("clients-v2")
        (state / "leases.json").unlink()
        (config / "added-later.conf").write_text("new")
        (config / "porta.env").write_text("PORTA_ADMIN_TOKEN=rotated\n")
        restored = backup("restore", newest).stdout
        self.assertFalse((config / "added-later.conf").exists())
        self.assertEqual((config / "porta.env").read_text(), "PORTA_ADMIN_TOKEN=secret\n")
        self.assertEqual((state / "clients.json").read_text(), "clients-v1")
        self.assertEqual((state / "leases.json").read_text(), "leases-v1")
        self.assertEqual((state / "downloads/porta-client").read_text(), "binary")
        undo = next(state.glob("restore-replaced-*"))
        self.assertEqual((undo / "state/clients.json").read_text(), "clients-v2")
        self.assertEqual((undo / "config/added-later.conf").read_text(), "new")
        self.assertIn("previous state kept in", restored)
        self.assertEqual(log.read_text().split("\n")[:2], ["stop porta.service", "start porta.service"])

    def test_documentation_links_and_anchors_resolve(self):
        def slug(heading):
            heading = re.sub(r"[`*_]", "", heading.strip().lower())
            return re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")

        documents = [path for path in ROOT.rglob("*.md")
                     if not {"target", "vendor", ".build", "node_modules"} & set(path.parts)
                     and not any(part.startswith(".automation") for part in path.parts)]
        anchors = {}
        for document in documents:
            seen, found = {}, set()
            for line in document.read_text().splitlines():
                heading = re.match(r"^#{1,6}\s+(.*)", line)
                if heading:
                    name = slug(heading.group(1))
                    found.add(name if name not in seen else f"{name}-{seen[name]}")
                    seen[name] = seen.get(name, 0) + 1
            anchors[document.resolve()] = found
        for document in documents:
            text = re.sub(r"```.*?```", "", document.read_text(), flags=re.DOTALL)
            for target in re.findall(r"\]\(([^)\s]+)\)", text):
                if re.match(r"^[a-z]+:", target):
                    continue
                path, _, fragment = target.partition("#")
                destination = (document.parent / path).resolve() if path else document.resolve()
                with self.subTest(document=str(document.relative_to(ROOT)), target=target):
                    self.assertTrue(destination.exists())
                    if fragment and destination.suffix == ".md":
                        self.assertIn(fragment, anchors[destination])

    def test_alert_rules_only_use_metrics_the_gateway_exports(self):
        # Without PyYAML, which release runners do not guarantee: every
        # porta_ identifier in the file is a metric name.
        rules = (ROOT / "deploy/prometheus/porta-alerts.yml").read_text()
        self.assertGreaterEqual(rules.count("- alert: "), 9)
        sources = "".join(
            path.read_text() for path in (ROOT / "rust/porta-server/src").rglob("*.rs")
        )
        for name in sorted(set(re.findall(r"\bporta_[a-z_]+", rules))):
            with self.subTest(metric=name):
                self.assertIn(f'"{name}"', sources)

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

    def test_client_builds_use_rust_without_go_tooling(self):
        # The only Go is the independent CONNECT-IP interop probe: its own
        # module, Makefile target and CI job, never part of a client build.
        def without_interop_probe(text):
            text = re.sub(r"(?ms)^build-masque-probe:.*?(?=^\S)", "", text)
            return re.sub(r"(?ms)^  masque-interop:.*?(?=^  \S|\Z)", "", text)

        build_sources = "\n".join(
            without_interop_probe((ROOT / path).read_text())
            for path in ("Makefile", ".github/workflows/ci.yml",
                         ".github/workflows/release.yml", ".github/workflows/live.yml")
        )
        for obsolete in ("setup-go", "gomobile", "gobind"):
            self.assertNotIn(obsolete, build_sources)
        self.assertIsNone(re.search(r"(?<![A-Za-z])go (?:build|test|run)\b", build_sources))
        go_sources = sorted(
            path.relative_to(ROOT)
            for directory in ("cmd", "internal", "mobile", "scripts", "experiments")
            for path in (ROOT / directory).rglob("*.go")
            if path.parent != ROOT / "experiments/masque-interop"
        )
        self.assertEqual(go_sources, [])
        for obsolete in (
            "go.mod",
            "go.sum",
            "scripts/build-android-aar.sh",
            "scripts/windows-up.ps1",
            "scripts/windows-down.ps1",
        ):
            self.assertFalse((ROOT / obsolete).exists(), obsolete)

    def test_android_workflows_do_not_request_removed_sdk_tools(self):
        for filename in ("ci.yml", "release.yml", "live.yml"):
            workflow = (ROOT / ".github/workflows" / filename).read_text()
            self.assertRegex(
                workflow,
                r"uses: android-actions/setup-android@[0-9a-f]{40}[^\n]*\n"
                r"        with:\n          packages: platform-tools\n",
                filename,
            )

    def test_android_rust_build_tracks_patched_transport_sources(self):
        gradle = (ROOT / "android/app/build.gradle.kts").read_text()
        for path in (
            "rust/porta-server/vendor/h3/Cargo.toml",
            "rust/porta-server/vendor/h3/src",
            "rust/porta-server/vendor/hyper/Cargo.toml",
            "rust/porta-server/vendor/hyper/src",
        ):
            self.assertIn(path, gradle)
        self.assertNotIn("vendor/quinn-proto", gradle)
        build = (ROOT / "scripts/build-android-rust.sh").read_text()
        self.assertIn("max-page-size=16384", build)
        self.assertIn("common-page-size=16384", build)
        self.assertIn("llvm-readelf", build)
        self.assertNotRegex(build, r"\bmapfile\b")

        manifest = (ROOT / "android/app/src/main/AndroidManifest.xml").read_text()
        self.assertIn("android.net.VpnService.SUPPORTS_ALWAYS_ON", manifest)
        self.assertRegex(
            manifest,
            r'android:name="android\.net\.VpnService\.SUPPORTS_ALWAYS_ON"\s+'
            r'android:value="false"',
        )

    def test_android_jni_entrypoints_are_not_obfuscated(self):
        rules = (ROOT / "android/app/proguard-rules.pro").read_text()
        for symbol in ("portamobile.Portamobile", "portamobile.ProofProvider",
                       "portamobile.Protector", "native <methods>"):
            self.assertIn(symbol, rules)

    def test_android_certificate_fetch_policy_is_scoped(self):
        namespace = "{http://schemas.android.com/apk/res/android}"
        manifest = ET.parse(ROOT / "android/app/src/main/AndroidManifest.xml").getroot()
        application = manifest.find("application")
        self.assertEqual(application.get(namespace + "usesCleartextTraffic"), "false")
        self.assertEqual(
            application.get(namespace + "networkSecurityConfig"),
            "@xml/network_security_config",
        )
        configuration = ET.parse(
            ROOT / "android/app/src/main/res/xml/network_security_config.xml"
        ).getroot()
        base = configuration.find("base-config")
        self.assertEqual(base.get("cleartextTrafficPermitted"), "false")
        self.assertEqual(
            [certificate.get("src") for certificate in base.findall("trust-anchors/certificates")],
            ["system"],
        )
        domains = configuration.findall("domain-config")
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].get("cleartextTrafficPermitted"), "true")
        self.assertEqual(
            [(domain.text, domain.get("includeSubdomains")) for domain in domains[0].findall("domain")],
            [("c.lencr.org", "true")],
        )
        self.assertEqual(
            [certificate.get("src") for certificate in configuration.findall(
                "debug-overrides/trust-anchors/certificates"
            )],
            ["user"],
        )
        for manifest_path in (ROOT / "android/app/src/debug").rglob("AndroidManifest.xml"):
            self.assertNotIn("networkSecurityConfig", manifest_path.read_text())

        service = (ROOT / "android/app/src/main/java/dev/porta/android/TunnelService.kt").read_text()
        # Porta itself stays outside the tunnel in every app mode; AppRulesTest
        # covers the rules.
        self.assertLess(
            service.index("appRules(configuration.appMode, configuration.apps, packageName)"),
            service.index("builder.establish()"),
        )

    def test_live_client_ci_is_credential_free_and_non_enrolling(self):
        workflow = (ROOT / ".github/workflows/live.yml").read_text()
        live = workflow[workflow.index("  live-windows:"):]
        self.assertNotIn("secrets.", live)
        self.assertIn("PORTA_TLS_TEST_URL: https://porta-dev.i-csu.org:8443", live)
        self.assertIn("--test platform_tls", live)
        self.assertIn("connectedDebugAndroidTest", live)
        self.assertIn("disk-size: 2048M", live)
        self.assertIn("/usr/share/dotnet", live)
        self.assertIn("/usr/local/share/boost", live)
        self.assertIn(
            "android.testInstrumentationRunnerArguments.portaTlsOrigin="
            "https://porta-dev.i-csu.org:8443",
            live,
        )
        probe = (ROOT / "rust/porta-client/tests/platform_tls.rs").read_text()
        self.assertIn("ci-live-probe-invalid-account", probe)
        self.assertIn("HTTP 401", probe)
        self.assertNotIn("NetworkManager", probe)
        self.assertNotIn("Tun::open", probe)
        self.assertEqual(workflow.count("github.ref == 'refs/heads/main'"), 3)

    def test_full_vpn_ci_is_protected_isolated_and_credentialed(self):
        workflow = (ROOT / ".github/workflows/live.yml").read_text()
        workflow_settings = workflow[:workflow.index("jobs:")]
        self.assertIn(
            "cancel-in-progress: ${{ github.event_name != 'schedule' && !inputs.vpn_e2e }}",
            workflow_settings,
        )
        vpn = workflow[
            workflow.index("  vpn-e2e-linux:"):workflow.index("  live-windows:")
        ]
        self.assertIn("environment: development", vpn)
        self.assertIn("permissions:\n      contents: read", vpn)
        self.assertIn("group: porta-development-vpn-e2e", vpn)
        self.assertIn("cancel-in-progress: false", vpn)
        self.assertIn("secrets.PORTA_E2E_TOKEN", vpn)
        self.assertIn("secrets.PORTA_E2E_LINUX_IDENTITY_BASE64", vpn)
        self.assertIn("./scripts/test-live-vpn.sh", vpn)
        self.assertIn(
            "PORTA_E2E_ARTIFACT_DIR: ${{ runner.temp }}/porta-vpn-e2e",
            vpn[vpn.index("- name: Exercise the real VPN data path"):],
        )
        self.assertNotIn("pull_request", vpn)
        before_exercise = vpn[:vpn.index("- name: Exercise the real VPN data path")]
        self.assertNotIn("secrets.PORTA_E2E_", before_exercise)
        harness = (ROOT / "scripts/test-live-vpn.sh").read_text()
        for fragment in [
            "ip netns add",
            "type veth",
            "masquerade",
            "ip daddr \"$gateway\" drop",
            "iptables -w -I FORWARD 1 -i \"$host_interface\" -j ACCEPT",
            "--ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -w -D FORWARD",
            "--transport \"$transport\"",
            "--identity \"$identity_path\"",
            "connected address=.* transport=$transport",
            "ip -4 route show proto 186",
            "ip -4 route get \"$gateway\"",
            "ping -n -c 3",
            "interface_mtu=$(<\"/sys/class/net/$interface/mtu\")",
            "df_payload=$((interface_mtu - 28))",
            "ping -n -c 1 -W 5 -M \"do\" -s \"$df_payload\"",
            "Porta-owned routes remain",
            "Porta leak-protection table remains",
            "private Porta gateway remains reachable",
            "sudo -n test -d \"$work/artifacts\"",
            "PORTA_E2E_ARTIFACT_DIR must not already exist",
        ]:
            self.assertIn(fragment, harness)
        self.assertNotIn("--token", harness)
        self.assertIn('install -o "$(id -u)" -g "$(id -g)" -m 0600', harness)
        self.assertNotIn(
            'chown -R "$(id -u):$(id -g)" "$artifact_directory"',
            harness,
        )

    def test_windows_release_uses_native_msvc_package(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertRegex(workflow, r"(?ms)^  windows:\n.*?runs-on: windows-latest")
        self.assertIn("--target x86_64-pc-windows-msvc", workflow)
        self.assertIn("name: porta-windows-release", workflow)
        self.assertIn("path: porta-client-windows-amd64.zip", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertNotIn("WebView2Loader.dll", workflow)
        package = (ROOT / "rust/porta-windows-package/src/lib.rs").read_text()
        for name in ("porta.exe", "porta-cli.exe", "wintun.dll"):
            self.assertIn(f'"{name}"', package)

    def test_windows_ci_proves_native_wfp_acceptance_ran(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        network = (ROOT / "rust/porta-client/src/windows/network.rs").read_text()
        self.assertIn('PORTA_WFP_NATIVE_TEST: "1"', workflow)
        self.assertIn("PORTA_WFP_NATIVE_TEST_MARKER", workflow)
        self.assertIn("native WFP rollback acceptance did not run", workflow)
        self.assertIn('std::env::var("PORTA_WFP_NATIVE_TEST")', network)
        self.assertIn('std::env::var_os("PORTA_WFP_NATIVE_TEST_MARKER")', network)
        self.assertIn("native_wfp_transaction_rollback_accepts_generated_policy", network)
        self.assertIn("FwpmTransactionAbort0", network)

    def test_native_client_security_failures_remain_fail_closed(self):
        windows_network = (
            ROOT / "rust/porta-client/src/windows/network.rs"
        ).read_text()
        helper = windows_network.split("let mut command = Command::new(powershell);", 1)[1]
        self.assertLess(helper.index(".env_clear()"), helper.index('.env("SystemRoot"'))

        android_service = (
            ROOT / "android/app/src/main/java/dev/porta/android/TunnelService.kt"
        ).read_text()
        permanent_failure = android_service.split(
            "} catch (error: PermanentTunnelException) {", 1
        )[1].split("} catch (error: Exception) {", 1)[0]
        self.assertIn("retainVpn = descriptor.get() != null", permanent_failure)
        self.assertIn(
            "if (!retainVpn || !holdVpnAfterTerminalFailure(runGeneration, finalStatus))",
            android_service,
        )
        blocked = android_service.split(
            "private fun holdVpnAfterTerminalFailure", 1
        )[1].split("private fun finishTunnel", 1)[0]
        self.assertIn("failClosed.set(true)", blocked)
        self.assertIn("outboundPackets.clear()", blocked)

        android_ui = (
            ROOT / "android/app/src/main/java/dev/porta/android/MainActivity.kt"
        ).read_text()
        self.assertIn(
            'value.startsWith("Waiting") || value.startsWith("Connection blocked")',
            android_ui,
        )
        client_docs = "\n".join(
            (ROOT / path).read_text() for path in ("README.md", "docs/clients.md")
        )
        self.assertNotRegex(client_docs, r"sudo\s+PORTA_TOKEN=")
        self.assertIn("--preserve-env=PORTA_TOKEN", client_docs)

    def test_native_client_ui_is_bilingual_and_traffic_updates_are_incremental(self):
        frontend = ROOT / "rust/porta-windows/frontend"
        html = (frontend / "index.html").read_text()
        javascript = (frontend / "app.js").read_text()
        css = (frontend / "app.css").read_text()
        desktop = (ROOT / "rust/porta-windows/src/desktop.rs").read_text()
        tauri = json.loads((ROOT / "rust/porta-windows/tauri.conf.json").read_text())

        self.assertIn('id="language-action"', html)
        self.assertIn('data-i18n="connectionLog"', html)
        self.assertNotIn('id="primary-connect"', html)
        self.assertNotIn('id="profile-transport"', html)
        self.assertNotIn("OpenLogFolder", javascript)
        self.assertIn('"zh-CN": {', javascript)
        self.assertIn('listen("porta:traffic"', javascript)
        self.assertIn("function profileSignature()", javascript)
        self.assertIn("if (canvas.width !== pixelWidth || canvas.height !== pixelHeight)", javascript)
        self.assertNotIn("open_log_folder", desktop)
        traffic_handler = javascript.split("function applyTraffic", 1)[1].split(
            "function renderTraffic", 1
        )[0]
        self.assertNotIn("renderProfiles", traffic_handler)
        self.assertIn("contain: content", css)

        progress = desktop.split("Event::Progress {", 1)[1].split(
            "Event::Reconnecting", 1
        )[0]
        self.assertIn("traffic = Some(traffic_from(&state))", progress)
        lightweight_publish = desktop.split("if let Some(traffic) = traffic", 1)[1].split(
            "if let Some(line) = activity", 1
        )[0]
        self.assertIn('app.emit("porta:traffic", traffic)', lightweight_publish)
        self.assertIn("return;", lightweight_publish)

        window = tauri["app"]["windows"][0]
        self.assertTrue(window["resizable"])
        self.assertGreaterEqual(window["width"], 480)
        self.assertGreaterEqual(window["height"], 680)

        def dictionary_keys(block):
            matches = re.findall(
                r'^\s+(?:"([^"]+)"|([A-Za-z][A-Za-z0-9]*)):',
                block,
                flags=re.MULTILINE,
            )
            return {quoted or bare for quoted, bare in matches}

        english_dictionary = javascript.split("en: {", 1)[1].split(
            '\n  },\n  "zh-CN"',
            1,
        )[0]
        chinese_dictionary = javascript.split('"zh-CN": {', 1)[1].split(
            "\n  },\n};",
            1,
        )[0]
        english_keys = dictionary_keys(english_dictionary)
        chinese_keys = dictionary_keys(chinese_dictionary)
        self.assertSetEqual(english_keys, chinese_keys)
        static_keys = set(re.findall(
            r'data-i18n(?:-placeholder|-aria-label|-title)?="([^"]+)"',
            html,
        ))
        self.assertTrue(static_keys <= english_keys)

        english = ET.parse(
            ROOT / "android/app/src/main/res/values/strings.xml"
        ).getroot()
        chinese = ET.parse(
            ROOT / "android/app/src/main/res/values-zh-rCN/strings.xml"
        ).getroot()
        english_names = {element.attrib["name"] for element in english.findall("string")}
        chinese_names = {element.attrib["name"] for element in chinese.findall("string")}
        self.assertSetEqual(english_names, chinese_names)

        manifest = ET.parse(ROOT / "android/app/src/main/AndroidManifest.xml").getroot()
        android_namespace = "{http://schemas.android.com/apk/res/android}"
        application = manifest.find("application")
        self.assertEqual(
            application.attrib[android_namespace + "localeConfig"],
            "@xml/locales_config",
        )
        android_service = (
            ROOT / "android/app/src/main/java/dev/porta/android/TunnelService.kt"
        ).read_text()
        self.assertIn(".setContentText(localizedNotificationText(text))", android_service)
        self.assertIn("R.string.notification_disconnect", android_service)
        android_activity = (
            ROOT / "android/app/src/main/java/dev/porta/android/MainActivity.kt"
        ).read_text()
        self.assertIn("R.string.reconnecting_secure_tunnel", android_activity)

    def test_benchmark_defaults_to_allowed_cpu_affinity(self):
        benchmark = (ROOT / "experiments/server-benchmark/run.sh").read_text()
        self.assertIn('Cpus_allowed_list:', benchmark)
        self.assertNotIn('PORTA_SERVER_BENCH_SERVER_CPUS:-"0,1"', benchmark)
        self.assertNotIn('PORTA_SERVER_BENCH_CLIENT_CPUS:-"2,3"', benchmark)

    def test_wintun_checksum_is_consistent(self):
        expected = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
        makefile = (ROOT / "Makefile").read_text().lower()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text().lower()
        self.assertIn(f"wintun_sha256 := {expected}", makefile)
        self.assertIn(expected, workflow)
        dll_expected = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
        tunnel = (ROOT / "rust/porta-client/src/windows/tun.rs").read_text().lower()
        self.assertIn(dll_expected, tunnel)

    def test_release_manifest_uses_pinned_signing_certificate(self):
        expected = (ROOT / "android/signing-certificate.sha256").read_text().strip()
        deploy = (ROOT / "scripts/deploy.sh").read_text().lower()
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn(f"release_signing_fingerprint={expected}", deploy)
        self.assertIn("SignReleaseManifest.java", workflow)
        self.assertIn("SHA256SUMS.sig", workflow)

    def test_documented_release_verification_blocks_extraction_on_failure(self):
        self.write_mock_command(
            "gh",
            """
if [ "${1:-} ${2:-}" = "release download" ]; then
    : > porta-deploy.tar.gz
    : > SHA256SUMS.sig
    : > release-signing-cert.der
    printf 'fixture  porta-deploy.tar.gz\\n' > SHA256SUMS
elif [ "${1:-} ${2:-}" = "auth token" ]; then
    printf 'test-token\\n'
else
    exit 1
fi
""",
        )
        self.write_mock_command(
            "openssl",
            """
case "$*" in
    *" -fingerprint "*)
        if [ "${FAIL_STAGE:-}" = certificate ]; then
            printf 'sha256 Fingerprint=%s\\n' \
                0000000000000000000000000000000000000000000000000000000000000000
        else
            printf 'sha256 Fingerprint=%s\\n' "$EXPECTED_FINGERPRINT"
        fi
        ;;
    *" -pubkey "*)
        printf '%s\\n' test-public-key
        ;;
    "dgst "*)
        [ "${FAIL_STAGE:-}" != signature ]
        ;;
    *)
        exit 1
        ;;
esac
""",
        )
        self.write_mock_command(
            "sha256sum",
            """
cat >/dev/null
[ "${FAIL_STAGE:-}" != checksum ]
""",
        )
        self.write_mock_command(
            "tar",
            """
: > "$EXTRACTED_MARKER"
mkdir porta
""",
        )

        for path in ("README.md", "docs/deployment.md"):
            script = self.deployment_bundle_script(path)
            expected = re.search(r"expected=([0-9a-f]{64})", script)
            self.assertIsNotNone(expected, path)
            for failure in ("certificate", "signature", "checksum", ""):
                with self.subTest(path=path, failure=failure or "none"):
                    directory = self.root / f"{Path(path).stem}-{failure or 'ok'}"
                    directory.mkdir()
                    marker = directory / "extracted"
                    result = subprocess.run(
                        ["bash", "-c", script],
                        cwd=directory,
                        env=self.env | {
                            "EXPECTED_FINGERPRINT": expected.group(1),
                            "EXTRACTED_MARKER": str(marker),
                            "FAIL_STAGE": failure,
                        },
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    if failure:
                        self.assertNotEqual(
                            result.returncode, 0, result.stdout + result.stderr
                        )
                        self.assertFalse(marker.exists())
                    else:
                        self.assertEqual(
                            result.returncode, 0, result.stdout + result.stderr
                        )
                        self.assertTrue(marker.is_file())

    def test_rust_release_uses_compatible_glibc_baseline_and_guard(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("runs-on: ubuntu-22.04", workflow)
        guard = re.search(r"grep -Eq '([^']*GLIBC[^']*)'", workflow)
        self.assertIsNotNone(guard)
        pattern = guard.group(1)
        for version, accepted in (("2.35", True), ("2.36", False), ("2.40", False)):
            result = subprocess.run(
                ["grep", "-Eq", pattern],
                input=f"GLIBC_{version}\n",
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode == 1, accepted, version)

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
