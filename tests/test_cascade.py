"""Pure tests: validation, scoped rules, persistence and rollback failures."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("cascade", Path(__file__).parents[1] / "cascade.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class Validation(unittest.TestCase):
    def test_bad_ports(self):
        for value in (0, 65536, -1, "1; reboot", "", "9999999999", True, "1.0", " 22", "+22"):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.port(value)

    def test_ports(self):
        for value in (1, 65535, "443", "0080"):
            self.assertEqual(c.port(value), int(value))

    def test_bad_addresses(self):
        for value in ("", "example.com", "1.2.3.999", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1",
                      "1.2.3.4; flush ruleset", "1.2.3.4\n", "255.255.255.255"):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.ipv4(value)

    def test_target_equal_listen(self):
        with self.assertRaises(c.Error):
            c.rule("tcp", "10.1.0.1", 443, "10.1.0.1", 443)

    def test_protocol(self):
        with self.assertRaises(c.Error):
            c.rule("icmp", "10.1.0.1", 443, "10.1.0.2", 443)

    def test_corrupt_state(self):
        state = c.empty_state()
        state["rules"] = [dict(proto="tcp", listen="10.1.0.1", incoming="443", target="10.2.0.2", outgoing=443)]
        state["previous_forward"] = "0"
        with self.assertRaises(c.Error):
            c.validate_state(state)

    def test_duplicate_state(self):
        state = c.empty_state()
        item = c.rule("tcp", "10.1.0.1", 443, "10.2.0.2", 443)
        state.update(rules=[item, item], previous_forward="0")
        with self.assertRaises(c.Error):
            c.validate_state(state)

    def test_unknown_table_refused(self):
        with self.assertRaises(c.Error):
            c.owns_table([{"table": {"family": "ip", "name": c.TABLE}}])

    def test_ownership_on_older_nft_json(self):
        objects = [{"table": {"family": "ip", "name": c.TABLE}},
                   {"rule": {"family": "ip", "table": c.TABLE, "chain": "ownership", "comment": c.OWNER}}]
        self.assertTrue(c.owns_table(objects))
        objects[1]["rule"]["table"] = "someone_else"
        with self.assertRaises(c.Error):
            c.owns_table(objects)

    @patch.object(c.shutil, "which", return_value=None)
    def test_foreign_forward_requires_acknowledgement(self, _):
        data = [{"chain": {"family": "inet", "table": "firewall", "name": "forward", "hook": "forward"}}]
        with self.assertRaises(c.Error):
            c.check_firewall(data, False)
        c.check_firewall(data, True)

    def test_scoped_nat(self):
        text = c.render([c.rule("udp", "10.1.0.1", 51820, "10.2.0.2", 51821)], True)
        self.assertIn("ip daddr 10.1.0.1 udp dport 51820", text)
        self.assertIn("ct original ip daddr 10.1.0.1 ct original proto-dst 51820", text)
        self.assertIn("ip daddr 10.2.0.2 udp dport 51821", text)
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("hook input", text)
        self.assertEqual(c.render([], True), "delete table ip cascade_v1\n")
        self.assertEqual(c.render([], False), "")


class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state = self.base / "state.json"
        self.forward = self.base / "ip_forward"
        self.forward.write_text("0\n")
        self.old = c.empty_state()
        self.new = copy.deepcopy(self.old)
        self.new["rules"] = [c.rule("tcp", "10.1.0.1", 8443, "10.2.0.2", 443)]
        for name, value in (("STATE", self.state), ("FORWARD", self.forward)):
            p = patch.object(c, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name, value in (("inventory", []), ("check_firewall", None), ("run", None), ("purge", None)):
            p = patch.object(c, name, return_value=value)
            setattr(self, name, p.start())
            self.addCleanup(p.stop)

    def test_save_and_clear_restore_forwarding(self):
        with patch.object(c, "apply"):
            c.transition(self.old, self.new)
            saved = c.load()
            self.assertEqual(saved["previous_forward"], "0")
            self.assertEqual(self.forward.read_text(), "1\n")
            cleared = copy.deepcopy(saved)
            cleared["rules"] = []
            c.transition(saved, cleared)
        self.assertEqual(self.forward.read_text(), "0\n")
        self.assertEqual(c.load()["rules"], [])
        self.purge.assert_called_once_with(self.new["rules"][0])

    def test_existing_forwarding_preserved(self):
        self.forward.write_text("1\n")
        with patch.object(c, "apply"):
            c.transition(self.old, self.new)
            saved = c.load()
            cleared = copy.deepcopy(saved)
            cleared["rules"] = []
            c.transition(saved, cleared)
        self.assertEqual(self.forward.read_text(), "1\n")

    def test_kernel_failure_rolls_back_and_does_not_save(self):
        with patch.object(c, "apply", side_effect=[c.Error("kernel failed"), None]) as apply:
            with self.assertRaisesRegex(c.Error, "kernel failed"):
                c.transition(self.old, self.new)
            self.assertEqual(apply.call_args_list[-1].args, ([],))
        self.assertFalse(self.state.exists())
        self.assertEqual(self.forward.read_text(), "0\n")

    def test_disk_failure_rolls_back(self):
        with patch.object(c, "apply") as apply, patch.object(c.os, "replace", side_effect=OSError("disk")):
            with self.assertRaisesRegex(OSError, "disk"):
                c.transition(self.old, self.new)
            self.assertEqual(apply.call_args_list[-1].args, ([],))
        self.assertFalse(self.state.exists())
        self.assertEqual(self.forward.read_text(), "0\n")
        self.assertEqual(list(self.base.glob(".state-*")), [])

    def test_dry_run_failure_does_not_change_forwarding(self):
        self.run.side_effect = c.Error("invalid nft")
        with patch.object(c, "apply"), self.assertRaises(c.Error):
            c.transition(self.old, self.new)
        self.assertEqual(self.forward.read_text(), "0\n")
        self.assertFalse(self.state.exists())

    def test_conntrack_error_not_hidden(self):
        with patch.object(c, "apply"):
            c.transition(self.old, self.new)
            saved = c.load()
            cleared = copy.deepcopy(saved)
            cleared["rules"] = []
            self.purge.side_effect = c.Error("permission denied")
            with self.assertRaisesRegex(c.Error, "соединения не очищены"):
                c.transition(saved, cleared)
        self.assertEqual(c.load()["rules"], [])

class Conntrack(unittest.TestCase):
    def test_empty_vs_failure(self):
        item = c.rule("tcp", "10.1.0.1", 8443, "10.2.0.2", 443)
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 1, "", "0 flow entries have been deleted.")) as run:
            c.purge(item)
            args = run.call_args.args[0]
            self.assertIn("--orig-dst", args)
            self.assertIn("--reply-src", args)
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 1, "", "Operation not permitted")):
            with self.assertRaises(c.Error):
                c.purge(item)


if __name__ == "__main__":
    unittest.main()
