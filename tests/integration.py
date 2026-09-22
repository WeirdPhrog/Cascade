#!/usr/bin/env python3
"""Real Linux kernel tests. All firewall changes occur in throwaway netns."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "cs" + uuid.uuid4().hex[:6]
CLIENT, RELAY, SERVER = [PREFIX + x for x in ("c", "r", "s")]
PROCESSES = []


def run(*args, input=None, ok=True):
    r = subprocess.run(args, input=input, text=True, capture_output=True, timeout=30)
    if ok and r.returncode:
        raise AssertionError(f"{args}: {r.stdout}\n{r.stderr}")
    return r


def ns(namespace, *args, **kw):
    return run("ip", "netns", "exec", namespace, *args, **kw)


def significant(text):
    # Builtin policy counters legitimately change while test traffic flows.
    # Preserve table identity, chain names/policies, all rules and rule order.
    return [" ".join(line.split()[:2]) if line.startswith(":") else line
            for line in text.splitlines() if line.startswith(("*", "-A", ":"))]


SERVER_CODE = r'''
import socket, threading, time
def tcp(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('10.200.2.2',port)); s.listen()
    while True:
        c,a=s.accept()
        with c:
            data=c.recv(4096); c.sendall(b'echo:'+data)
def udp(port):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.200.2.2',port))
    while True:
        data,a=s.recvfrom(4096); s.sendto(b'echo:'+data,a)
for port in (5201,5202):
    for f in (tcp,udp): threading.Thread(target=f,args=(port,),daemon=True).start()
while True: time.sleep(60)
'''

CLIENT_CODE = r'''
import socket,sys
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM if sys.argv[1]=='tcp' else socket.SOCK_DGRAM)
s.settimeout(1)
s.connect(('10.200.1.1', int(sys.argv[2])))
s.send(b'cascade-test')
assert s.recv(4096)==b'echo:cascade-test'
'''


def relay_command(state_dir, *args, ok=True):
    # Same installed code; only state storage is isolated per test fixture.
    code = ("import sys; from pathlib import Path; "
            f"sys.path.insert(0,{str(ROOT)!r}); import cascade; "
            f"cascade.STATE=Path({str(state_dir / 'state.json')!r}); "
            "cascade.main()")
    return ns(RELAY, "python3", "-c", code, *args, ok=ok)


def connect(proto, port, succeeds=True):
    result = ns(CLIENT, "python3", "-c", CLIENT_CODE, proto, str(port), ok=False)
    assert (result.returncode == 0) == succeeds, result.stderr


def main():
    assert os.geteuid() == 0, "Run with sudo"
    with tempfile.TemporaryDirectory(prefix="cascade-integration-") as tmp:
        state = Path(tmp)
        for name in (CLIENT, RELAY, SERVER):
            run("ip", "netns", "add", name)
            ns(name, "ip", "link", "set", "lo", "up")
        for a, b, aname, bname, aip, bip in (
            (CLIENT, RELAY, "client0", "left0", "10.200.1.2/24", "10.200.1.1/24"),
            (RELAY, SERVER, "right0", "server0", "10.200.2.1/24", "10.200.2.2/24"),
        ):
            ns(a, "ip", "link", "add", aname, "type", "veth", "peer", "name", bname)
            ns(a, "ip", "link", "set", bname, "netns", b)
            for n, dev, addr in ((a, aname, aip), (b, bname, bip)):
                ns(n, "ip", "addr", "add", addr, "dev", dev)
                ns(n, "ip", "link", "set", dev, "up")
        # The server has no return route to CLIENT: a working reply proves scoped SNAT.
        ns(RELAY, "sysctl", "-w", "net.ipv4.ip_forward=0")
        sentinel = 'table inet sentinel {\n chain input {\n type filter hook input priority 0; policy accept; tcp dport 65000 counter drop;\n }\n}\n'
        ns(RELAY, "nft", "-f", "-", input=sentinel)
        before = ns(RELAY, "nft", "list", "table", "inet", "sentinel").stdout
        ns(RELAY, "iptables", "-P", "FORWARD", "DROP")
        ns(RELAY, "iptables", "-N", "DOCKER-USER")
        ns(RELAY, "iptables", "-A", "DOCKER-USER", "-j", "RETURN")
        ns(RELAY, "iptables", "-I", "FORWARD", "-j", "DOCKER-USER")
        foreign_filter = ns(RELAY, "iptables-save", "-t", "filter").stdout
        proc = subprocess.Popen(["ip", "netns", "exec", SERVER, "python3", "-u", "-c", SERVER_CODE])
        PROCESSES.append(proc)
        for _ in range(50):
            if "5201" in ns(SERVER, "ss", "-lnt").stdout and "5202" in ns(SERVER, "ss", "-lnu").stdout:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Echo server failed to start")
        def command(*args, **kw):
            return relay_command(state, *args, **kw)
        def add(proto, incoming, outgoing="5201", extra=()):
            return command("add", "--proto", proto, "--listen", "10.200.1.1", "--in-port", str(incoming),
                           "--target", "10.200.2.2", "--out-port", outgoing, *extra)

        # Upgrade a saved v1 configuration and remove only its owned nft table.
        migrated = dict(proto="tcp", listen="10.200.1.1", incoming=4201, target="10.200.2.2", outgoing=5201)
        (state / "state.json").write_text(json.dumps({"version": 1, "rules": [migrated], "previous_forward": "0", "external_firewall": True}))
        ns(RELAY, "nft", "-f", "-", input='table ip cascade_v1 {\n chain ownership {\n counter comment "Cascade managed table v1"\n }\n}\n')
        command("apply")
        assert ns(RELAY, "nft", "list", "table", "ip", "cascade_v1", ok=False).returncode != 0
        assert json.loads((state / "state.json").read_text())["version"] == 2
        connect("tcp", 4201)
        add("tcp", 4201)
        add("udp", 4201)
        add("tcp", 4202)  # same destination as 4201; must survive deleting 4201
        for proto in ("tcp", "udp"):
            connect(proto, 4201)
        add("tcp", 4201)  # idempotent re-add
        assert len(json.loads((state / "state.json").read_text())["rules"]) == 3
        add("tcp", 4201, "5202", ("--replace",))
        connect("tcp", 4201)
        # Shared forwarding must stay enabled for other VPNs after stop/clear.
        command("stop")
        assert ns(RELAY, "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "1"
        connect("tcp", 4201, False)
        command("apply")
        connect("tcp", 4201)
        connect("udp", 4201)
        command("delete", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4201")
        connect("tcp", 4201, False)
        remaining = ns(RELAY, "conntrack", "-L", "-p", "tcp", "--orig-dst", "10.200.1.1", "--orig-port-dst", "4201").stdout
        assert not remaining.strip(), remaining
        connect("tcp", 4202)
        connect("udp", 4201)
        add("tcp", 4203)
        connect("tcp", 4203)
        command("delete", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4203")
        connect("tcp", 4202)
        # Deleting an absent rule is safe and repeatable.
        command("delete", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4201")
        assert command("add", "--proto", "tcp", "--in-port", "0", "--target", "10.200.2.2", ok=False).returncode != 0
        # A foreign DNAT reserves its port, including ranges. No socket required.
        ns(RELAY, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "4300:4310", "-j", "DNAT", "--to-destination", "10.200.2.2:5201")
        bad = command("add", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4305", "--target", "10.200.2.2", ok=False)
        assert bad.returncode != 0 and "DNAT/REDIRECT" in bad.stderr
        # A local listener must never be hijacked, even with --replace.
        listener = subprocess.Popen(["ip", "netns", "exec", RELAY, "python3", "-c",
                                     "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',4400)); s.listen(); time.sleep(300)"])
        PROCESSES.append(listener)
        for _ in range(50):
            if "4400" in ns(RELAY, "ss", "-lnt").stdout:
                break
            time.sleep(0.05)
        bad = command("add", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4400", "--target", "10.200.2.2", "--replace", ok=False)
        assert bad.returncode != 0 and "занят локальным" in bad.stderr
        # Independent native nftables forwarding remains explicitly unsupported.
        ns(RELAY, "nft", "-f", "-", input='table inet external {\n chain forward {\n type filter hook forward priority 0; policy drop;\n }\n}\n')
        bad = command("add", "--proto", "tcp", "--listen", "10.200.1.1", "--in-port", "4203", "--target", "10.200.2.2", ok=False)
        assert bad.returncode != 0 and "nftables firewall" in bad.stderr
        # Cleanup must still work with an external firewall appearing after install.
        command("clear", "--yes")
        assert ns(RELAY, "nft", "list", "table", "inet", "external").returncode == 0
        assert ns(RELAY, "iptables", "-t", "nat", "-S", "CSCD_DNAT", ok=False).returncode != 0
        assert ns(RELAY, "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "1"
        after_filter = ns(RELAY, "iptables-save", "-t", "filter").stdout
        assert significant(after_filter) == significant(foreign_filter), (significant(after_filter), significant(foreign_filter))
        assert ns(RELAY, "nft", "list", "table", "inet", "sentinel").stdout == before
        assert json.loads((state / "state.json").read_text())["rules"] == []
        command("clear", "--yes")
        print("PASS: TCP/UDP, SNAT, replacement, reload, scoped deletion, foreign firewall preservation, cleanup")


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in PROCESSES:
            p.terminate()
            p.wait(timeout=5)
        for name in (CLIENT, RELAY, SERVER):
            run("ip", "netns", "delete", name, ok=False)
