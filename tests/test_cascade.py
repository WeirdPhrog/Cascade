import copy
import contextlib
import importlib.util
import json
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

    def test_unknown_options_refused(self):
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                c.parser().parse_args(["add", "--proto", "tcp", "--in-port", "8443", "--target", "10.2.0.2", "--unknown-option"])


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
    @patch.object(c, "route_to", return_value={"dev": "eth0"})
    @patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    def test_docker_binding_without_listener(self, *_):
        with patch.object(c, "docker_bindings", return_value=[("tcp", "0.0.0.0", 8443, "amnezia")]):
            with self.assertRaisesRegex(c.Error, "Docker"):
                c.check_ports([ITEM], EMPTY)
        with patch.object(c, "docker_bindings", return_value=[("udp", "0.0.0.0", 8443, "amnezia")]):
            c.check_ports([ITEM], EMPTY)

    def test_docker_failure_does_not_skip_port_check(self):
        with patch.object(c.Path, "exists", return_value=True), patch.object(c, "run", side_effect=c.Error("Docker unavailable")):
            with self.assertRaisesRegex(c.Error, "Docker unavailable"):
                c.docker_bindings()

    def test_local_broadcast_and_unreachable_routes_refused(self):
        for kind in ("local", "broadcast", "unreachable", "blackhole"):
            with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps([dict(type=kind, dev="eth0")]), "")):
                with self.assertRaises(c.Error):
                    c.route_to("10.2.0.2")
        with patch.object(c, "run", side_effect=c.Error("Network unreachable")):
            with self.assertRaises(c.Error):
                c.route_to("10.2.0.2")

    def test_missing_nft_is_not_treated_as_empty_firewall(self):
        with patch.object(c, "run", side_effect=FileNotFoundError("nft")):
            with self.assertRaises(FileNotFoundError):
                c.nft_inventory()


class Menu(unittest.TestCase):
    def test_invalid_address_is_reprompted_before_port(self):
        inputs = ["1", "10.2.0.2", "bad-ip", "10.1.0.1", "8443", "", "0"]
        with patch("builtins.input", side_effect=inputs), patch("builtins.print"), \
                patch.object(c, "route_to", return_value={"dev": "eth0"}), \
                patch.object(c, "local_addresses", return_value={"10.1.0.1"}), \
                patch.object(c, "locked", side_effect=lambda: contextlib.nullcontext()), \
                patch.object(c, "load", return_value=c.empty_state()), \
                patch.object(c, "Firewall"), patch.object(c, "check_ports"), patch.object(c, "execute") as execute:
            c.menu()
        args = execute.call_args.args[0]
        self.assertEqual((args.listen, args.in_port, args.out_port), ("10.1.0.1", "8443", "8443"))


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

    def test_mixed_backend_raw_rules_refused(self):
        answers = [subprocess.CompletedProcess([], 0, "iptables v1.8 (nf_tables)", ""),
                   subprocess.CompletedProcess([], 0, "*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j DROP\nCOMMIT", "")]
        with patch.object(c, "run", side_effect=answers), patch.object(c.shutil, "which", return_value="/usr/sbin/iptables-legacy-save"):
            with self.assertRaisesRegex(c.Error, "Одновременно"):
                c.Firewall().preflight()

    def test_other_backend_drop_not_hidden_by_later_table(self):
        text = "*filter\n:OUTPUT DROP [0:0]\nCOMMIT\n*nat\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
        answers = [subprocess.CompletedProcess([], 0, "iptables v1.8 (nf_tables)", ""),
                   subprocess.CompletedProcess([], 0, text, "")]
        with patch.object(c, "run", side_effect=answers), patch.object(c.shutil, "which", return_value="/usr/sbin/iptables-legacy-save"):
            with self.assertRaisesRegex(c.Error, "Одновременно"):
                c.Firewall().preflight()

    def test_standard_docker_raw_chain_allowed_native_chain_refused(self):
        fw = c.Firewall.__new__(c.Firewall)
        fw.backend = fw.default = "nft"
        raw = dict(family="ip", table="raw", name="PREROUTING", hook="prerouting", type="filter", prio=-300)
        with patch.object(c.shutil, "which", return_value=None):
            with patch.object(c, "nft_inventory", return_value=[{"chain": raw}]):
                fw.preflight()
            for change in (dict(name="custom"), dict(prio=-301), dict(table="docker-bridges"), dict(family="inet")):
                with patch.object(c, "nft_inventory", return_value=[{"chain": dict(raw, **change)}]):
                    with self.assertRaisesRegex(c.Error, "nftables firewall"):
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
        for name, value in (("Firewall", self.fw), ("check_ports", None), ("purge", None)):
            p = patch.object(c, name, return_value=value)
            setattr(self, name, p.start())
            self.addCleanup(p.stop)

    def test_clear_does_not_disable_shared_forwarding(self):
        c.transition(self.old, self.new)
        saved = c.load()
        self.assertEqual(saved["backend"], "nft")
        self.purge.reset_mock()
        c.transition(saved, dict(saved, rules=[]))
        self.assertEqual(self.forward.read_text(), "1\n")
        self.assertEqual(c.load()["rules"], [])
        self.assertIsNone(c.load()["backend"])
        self.purge.assert_called_once_with(ITEM)

    def test_empty_apply_does_not_pin_backend(self):
        c.transition(self.old, self.old)
        self.assertIsNone(c.load()["backend"])

    def test_apply_expires_only_local_attempts_before_dnat(self):
        c.transition(self.new, self.new)
        self.purge.assert_called_once_with(dict(ITEM, target=ITEM["listen"], outgoing=ITEM["incoming"]))

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

    def test_conntrack_failure_keeps_state_for_retry(self):
        c.transition(self.old, self.new)
        saved = c.load()
        before = self.state.read_bytes()
        self.fw.apply.reset_mock()
        self.purge.side_effect = c.Error("permission denied")
        with self.assertRaisesRegex(c.Error, "permission denied"):
            c.transition(saved, dict(saved, rules=[]))
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(self.fw.apply.call_count, 3)
        self.purge.side_effect = None
        c.transition(saved, dict(saved, rules=[]))
        self.assertEqual(c.load()["rules"], [])

    def test_interrupted_apply_rolls_back(self):
        self.fw.apply.side_effect = [None, KeyboardInterrupt(), None]
        with self.assertRaises(KeyboardInterrupt):
            c.transition(self.old, self.new)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.fw.apply.call_count, 3)


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
