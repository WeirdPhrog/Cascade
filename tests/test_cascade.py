import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SPEC = importlib.util.spec_from_file_location("cascade", Path(__file__).parents[1] / "cascade.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
ITEM = c.rule("tcp", "10.1.0.1", 8443, "10.2.0.2", 443)
EMPTY = {"nat": c.parse_save(":PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]"),
         "filter": c.parse_save(":FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -j RETURN")}


class Validation(unittest.TestCase):
    def test_bad_ports(self):
        for value in (0, 65536, -1, "1; reboot", "", "9999999999", True, "1.0", " 22", "+22"):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.port(value)

    def test_valid_ports(self):
        for value in (1, 65535, "443", "0080"):
            self.assertEqual(c.port(value), int(value))

    def test_bad_addresses(self):
        for value in ("", "example.com", "1.2.3.999", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "1.2.3.4; reboot", "255.255.255.255"):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.ipv4(value)

    def test_bad_protocol_and_local_target(self):
        for proto, target in (("icmp", "10.2.0.2"), ("tcp", "10.1.0.1")):
            with self.assertRaises(c.Error):
                c.rule(proto, "10.1.0.1", 443, target, 443)

    def test_duplicate_and_corrupt_state(self):
        for item in (dict(ITEM, incoming="8443"), dict(ITEM, target="bad")):
            with self.assertRaises(c.Error):
                c.validate_state(dict(version=2, backend="nft", rules=[item]))
        with self.assertRaises(c.Error):
            c.validate_state(dict(version=2, backend="nft", rules=[ITEM, ITEM]))

    def test_v1_upgrade_preserves_rules(self):
        old = dict(version=1, rules=[ITEM], previous_forward="0", external_firewall=True)
        self.assertEqual(c.validate_state(old), dict(version=2, rules=[ITEM], backend=None))

    def test_no_safety_bypass_flags(self):
        with patch("sys.stderr"):
            for flag in ("--allow-local-port", "--external-firewall"):
                with self.assertRaises(SystemExit):
                    c.parser().parse_args(["add", "--proto", "tcp", "--in-port", "8443", "--target", "10.2.0.2", flag])


class PortProtection(unittest.TestCase):
    def test_socket_address_and_protocol_scope(self):
        for address in ("0.0.0.0", "*", "[::]", "10.1.0.1", "[::ffff:10.1.0.1]"):
            self.assertTrue(c.socket_conflict(ITEM, f"LISTEN 0 4096 {address}:8443 0.0.0.0:*"))
        self.assertFalse(c.socket_conflict(ITEM, "LISTEN 0 4096 10.1.0.9:8443 0.0.0.0:*"))
        self.assertFalse(c.socket_conflict(ITEM, "LISTEN 0 4096 0.0.0.0:8444 0.0.0.0:*"))
        self.assertTrue(c.socket_conflict(ITEM, "ESTAB 0 0 10.1.0.1:8443 10.1.0.4:22"))

    def test_nat_ranges_redirect_and_negation(self):
        for line in (
            "-A DOCKER -p tcp --dport 8443 -j DNAT --to-destination 172.17.0.2:443",
            "-A PREROUTING -p tcp --dport 8400:8500 -j REDIRECT --to-ports 80",
            "-A PREROUTING -p tcp -m multiport --dports 22,8443,9443 -j DNAT --to-destination 10.4.0.1",
            "-A PREROUTING -d 10.1.0.0/24 -p tcp -j DNAT --to-destination 10.4.0.1",
            "-A PREROUTING ! -p udp --dport 8443 -j REDIRECT",
        ):
            with self.subTest(line=line):
                self.assertTrue(c.nat_conflict(ITEM, line))
        for line in (
            "-A DOCKER -p udp --dport 8443 -j DNAT --to-destination 172.17.0.2:443",
            "-A PREROUTING -d 10.1.0.9/32 -p tcp --dport 8443 -j REDIRECT",
            "-A PREROUTING -p tcp ! --dport 8443 -j REDIRECT",
            "-A PREROUTING ! -d 10.1.0.1 -p tcp --dport 8443 -j REDIRECT",
            "-A CSCD_DNAT -p tcp --dport 8443 -j DNAT --to-destination 10.2.0.2:443",
        ):
            with self.subTest(line=line):
                self.assertFalse(c.nat_conflict(ITEM, line))

    @patch.object(c, "local_addresses", return_value={"10.1.0.1"})
    @patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    def test_docker_binding_without_listener(self, *_):
        with patch.object(c, "docker_bindings", return_value=[("tcp", "0.0.0.0", 8443, "amnezia")]):
            with self.assertRaisesRegex(c.Error, "Docker"):
                c.check_ports([ITEM], EMPTY)
        with patch.object(c, "docker_bindings", return_value=[("udp", "0.0.0.0", 8443, "amnezia")]):
            c.check_ports([ITEM], EMPTY)


class ScopedFirewall(unittest.TestCase):
    def test_only_owned_chains_are_rebuilt(self):
        text = c.render("filter", EMPTY["filter"], c.desired("filter", [ITEM], EMPTY["filter"]))
        self.assertIn("-I DOCKER-USER 1", text)
        self.assertIn("-I FORWARD 1", text)
        self.assertIn("--ctorigdst 10.1.0.1 --ctorigdstport 8443", text)
        self.assertIn("--ctreplsrc 10.2.0.2 --ctreplsrcport 443", text)
        self.assertNotIn(":FORWARD", text)
        self.assertNotIn(":DOCKER-USER", text)
        self.assertNotIn("-F FORWARD", text)

    def test_cleanup_removes_our_hooks_only(self):
        snap = c.parse_save(":FORWARD DROP [0:0]\n:CSCD_FWD - [0:0]\n"
                            "-A FORWARD -j DOCKER-USER\n"
                            "-A FORWARD -m comment --comment cascade:v2 -j CSCD_FWD\n"
                            "-A CSCD_FWD -m comment --comment cascade:v2")
        text = c.render("filter", snap, {"chains": {}, "hooks": []})
        self.assertIn("-X CSCD_FWD", text)
        self.assertIn("-D FORWARD -m comment --comment cascade:v2 -j CSCD_FWD", text)
        self.assertNotIn("DOCKER-USER", text)

    def test_foreign_name_collision_and_reference_refused(self):
        for text in (":CSCD_FWD - [0:0]", ":CSCD_FWD - [0:0]\n-A CSCD_FWD -j ACCEPT",
                     ":CSCD_FWD - [0:0]\n-A CSCD_FWD -m comment --comment cascade:v2\n-A FORWARD -j CSCD_FWD"):
            with self.assertRaises(c.Error):
                c.owned("filter", c.parse_save(text))

    def test_forwarding_backend_change_is_not_silent(self):
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "iptables v1.8 (nf_tables)", "")):
            fw = c.Firewall("legacy")
        with self.assertRaisesRegex(c.Error, "backend"):
            fw.preflight()


class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state = self.base / "state.json"
        self.forward = self.base / "ip_forward"
        self.forward.write_text("0\n")
        self.old = c.empty_state()
        self.new = dict(version=2, backend=None, rules=[ITEM])
        self.fw = MagicMock(backend="nft")
        self.fw.snapshot.return_value = copy.deepcopy(EMPTY)
        for name, value in (("STATE", self.state), ("FORWARD", self.forward)):
            p = patch.object(c, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name, value in (("Firewall", self.fw), ("old_nft_table", None), ("check_ports", None), ("purge", None)):
            p = patch.object(c, name, return_value=value)
            setattr(self, name, p.start())
            self.addCleanup(p.stop)

    def test_clear_does_not_disable_shared_forwarding(self):
        c.transition(self.old, self.new)
        saved = c.load()
        self.assertEqual(saved["backend"], "nft")
        c.transition(saved, dict(saved, rules=[]))
        self.assertEqual(self.forward.read_text(), "1\n")
        self.assertEqual(c.load()["rules"], [])
        self.purge.assert_called_once_with(ITEM)

    def test_dry_run_failure_changes_nothing(self):
        self.fw.apply.side_effect = c.Error("invalid")
        with self.assertRaises(c.Error):
            c.transition(self.old, self.new)
        self.assertEqual(self.forward.read_text(), "0\n")
        self.assertFalse(self.state.exists())
        self.assertEqual(self.fw.apply.call_count, 1)

    def test_partial_kernel_failure_rolls_back_owned_rules(self):
        self.fw.apply.side_effect = [None, c.Error("kernel failed"), None]
        with self.assertRaisesRegex(c.Error, "kernel failed"):
            c.transition(self.old, self.new)
        self.assertFalse(self.state.exists())
        backup = self.fw.apply.call_args.args[0]
        self.assertEqual(backup, {t: {"chains": {}, "hooks": []} for t in c.CHAINS})

    def test_disk_failure_rolls_back(self):
        with patch.object(c.os, "replace", side_effect=OSError("disk")):
            with self.assertRaisesRegex(OSError, "disk"):
                c.transition(self.old, self.new)
        self.assertEqual(self.fw.apply.call_count, 3)
        self.assertFalse(self.state.exists())
        self.assertEqual(list(self.base.glob(".state-*")), [])

    def test_conflict_prevents_any_mutation(self):
        self.check_ports.side_effect = c.Error("busy")
        with self.assertRaisesRegex(c.Error, "busy"):
            c.transition(self.old, self.new)
        self.fw.apply.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_cleanup_available_even_with_new_conflict(self):
        self.check_ports.side_effect = c.Error("busy")
        c.transition(self.new, dict(self.new, rules=[]), check=False)
        self.check_ports.assert_not_called()

    def test_conntrack_error_is_reported_after_saved_deletion(self):
        self.purge.side_effect = c.Error("permission denied")
        with self.assertRaisesRegex(c.Error, "соединения не очищены"):
            c.transition(self.new, dict(self.new, rules=[]))
        self.assertEqual(c.load()["rules"], [])


class Conntrack(unittest.TestCase):
    def test_empty_vs_failure(self):
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 1, "", "0 flow entries have been deleted.")) as run:
            c.purge(ITEM)
            self.assertIn("--orig-dst", run.call_args.args[0])
            self.assertIn("--reply-src", run.call_args.args[0])
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 1, "", "Operation not permitted")):
            with self.assertRaises(c.Error):
                c.purge(ITEM)


if __name__ == "__main__":
    unittest.main()
