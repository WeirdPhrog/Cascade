#!/usr/bin/env python3
"""Expendable GitHub Actions VM only: real Docker, no userland proxy."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from integration import ROOT, SERVER_CODE, CLIENT_CODE, run, ns, significant

PREFIX = "cs" + uuid.uuid4().hex[:6]
CLIENT, SERVER = PREFIX + "c", PREFIX + "s"
CONTAINER, STOPPED = PREFIX + "vpn", PREFIX + "stopped"
CONFIG = Path("/etc/docker/daemon.json")


def main():
    assert os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true", "Disposable CI VM only"
    original_config = CONFIG.read_bytes() if CONFIG.exists() else None
    config = json.loads(original_config or b"{}")
    config["userland-proxy"] = False
    CONFIG.write_text(json.dumps(config))
    run("systemctl", "restart", "docker")
    processes = []
    state = None
    try:
        # Container rules reproduce Amnezia's FORWARD/MASQUERADE setup, while
        # an echo service lets us verify packet delivery without VPN credentials.
        run("docker", "build", "-t", "cascade-vpn-fixture", "-f", "tests/Dockerfile.vpn", str(ROOT))
        run("docker", "run", "-d", "--name", CONTAINER, "--cap-add", "NET_ADMIN", "--restart", "always",
            "-p", "45010:5201/tcp", "-p", "45010:5201/udp", "cascade-vpn-fixture")
        run("docker", "create", "--name", STOPPED, "-p", "45011:5201/tcp", "cascade-vpn-fixture")
        for name in (CLIENT, SERVER):
            run("ip", "netns", "add", name)
            ns(name, "ip", "link", "set", "lo", "up")
        for name, dev, peer, host_ip, remote_ip in (
            (CLIENT, PREFIX + "l", "client0", "10.200.1.1/24", "10.200.1.2/24"),
            (SERVER, PREFIX + "r", "server0", "10.200.2.1/24", "10.200.2.2/24"),
        ):
            run("ip", "link", "add", dev, "type", "veth", "peer", "name", peer)
            run("ip", "link", "set", peer, "netns", name)
            run("ip", "addr", "add", host_ip, "dev", dev)
            run("ip", "link", "set", dev, "up")
            ns(name, "ip", "addr", "add", remote_ip, "dev", peer)
            ns(name, "ip", "link", "set", peer, "up")
        proc = subprocess.Popen(["ip", "netns", "exec", SERVER, "python3", "-u", "-c", SERVER_CODE])
        processes.append(proc)
        for _ in range(60):
            if "5201" in ns(SERVER, "ss", "-lnt").stdout and "5201" in run("docker", "exec", CONTAINER, "ss", "-lnu").stdout:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Echo services did not start")
        run("iptables", "-P", "FORWARD", "DROP")

        def connect(proto, port):
            ns(CLIENT, "python3", "-c", CLIENT_CODE, proto, str(port))

        for proto in ("tcp", "udp"):
            connect(proto, 45010)
        with tempfile.TemporaryDirectory(prefix="cascade-docker-") as tmp:
            state = Path(tmp) / "state.json"
            def command(*args, ok=True):
                code = (f"import sys; from pathlib import Path; sys.path.insert(0,{str(ROOT)!r}); import cascade; "
                        f"cascade.STATE=Path({str(state)!r}); cascade.main()")
                return run("python3", "-c", code, *args, ok=ok)
            def add(proto, value, ok=True):
                return command("add", "--proto", proto, "--listen", "10.200.1.1", "--in-port", str(value),
                               "--target", "10.200.2.2", "--out-port", "5201", ok=ok)
            try:
                for value in (45010, 45011):
                    bad = add("tcp", value, ok=False)
                    assert bad.returncode != 0 and "Docker" in bad.stderr, bad.stderr
                    assert not state.exists(), "Rejected port was persisted"
                for proto in ("tcp", "udp"):
                    add(proto, 24443)
                    connect(proto, 24443)
                    connect(proto, 45010)
                # Restart the real daemon without re-applying Cascade afterwards.
                run("systemctl", "restart", "docker")
                for _ in range(60):
                    if run("docker", "inspect", "-f", "{{.State.Running}}", CONTAINER).stdout.strip() == "true":
                        probe = ns(CLIENT, "python3", "-c", CLIENT_CODE, "tcp", "45010", ok=False)
                        if probe.returncode == 0:
                            break
                    time.sleep(0.2)
                else:
                    raise AssertionError("Container did not recover after Docker restart")
                for proto in ("tcp", "udp"):
                    connect(proto, 24443)
                    connect(proto, 45010)
                # Snapshot after restart; cleanup must leave Docker and VPN rules intact.
                before = run("iptables-save").stdout
                vpn_before = run("docker", "exec", CONTAINER, "iptables-save").stdout
                command("clear", "--yes")
                def foreign(text):
                    return [line for line in significant(text) if "CSCD_" not in line]
                assert foreign(run("iptables-save").stdout) == foreign(before)
                assert foreign(run("docker", "exec", CONTAINER, "iptables-save").stdout) == foreign(vpn_before)
                assert run("sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "1"
                for proto in ("tcp", "udp"):
                    connect(proto, 45010)
                assert run("iptables", "-t", "nat", "-S", "CSCD_DNAT", ok=False).returncode != 0
                print("PASS: real Docker without proxy, stopped-port reservation, TCP/UDP coexistence, daemon restart, scoped removal")
            finally:
                command("clear", "--yes", ok=False)
    finally:
        for p in processes:
            p.terminate()
            p.wait(timeout=5)
        for name in (CLIENT, SERVER):
            run("ip", "netns", "delete", name, ok=False)
        run("docker", "rm", "-f", CONTAINER, STOPPED, ok=False)
        if original_config is None:
            CONFIG.unlink(missing_ok=True)
        else:
            CONFIG.write_bytes(original_config)
        run("systemctl", "restart", "docker", ok=False)


if __name__ == "__main__":
    main()
