#!/usr/bin/python3 -I
"""IPv4 relay: only tagged Cascade chains and hooks are modified."""
import argparse
import contextlib
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

VERSION = "2.0.0"
TAG = "cascade:v2"
CHAINS = {"nat": ("CSCD_DNAT", "CSCD_SNAT"), "filter": ("CSCD_FWD",)}
STATE = Path("/etc/cascade/state.json")
FORWARD = Path("/proc/sys/net/ipv4/ip_forward")
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class Error(Exception):
    pass


def run(args, *, data=None, ok=(0,)):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            timeout=60, env={"PATH": SAFE_PATH, "LC_ALL": "C"})
    if result.returncode not in ok:
        raise Error(f"{' '.join(args)}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError) as exc:
        raise Error("Нужен IPv4-адрес, например 203.0.113.10.") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
        raise Error("Нельзя использовать loopback, multicast, 0.0.0.0 или broadcast.")
    return str(address)


def port(value):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,5}", str(value)) or not 1 <= int(value) <= 65535:
        raise Error("Порт должен быть целым числом 1–65535.")
    return int(value)


def rule(proto, listen, incoming, target, outgoing):
    if proto not in ("tcp", "udp"):
        raise Error("Поддерживаются только tcp и udp.")
    item = dict(proto=proto, listen=ipv4(listen), incoming=port(incoming),
                target=ipv4(target), outgoing=port(outgoing))
    if item["listen"] == item["target"]:
        raise Error("Назначение должно находиться на другом сервере.")
    return item


def key(item):
    return item["proto"], item["listen"], item["incoming"]


def empty_state():
    return {"version": 2, "rules": [], "backend": None}


def validate_state(state):
    if not isinstance(state, dict) or type(state.get("version")) is not int:
        raise Error("Повреждён state.json.")
    if state["version"] == 1:
        if set(state) != {"version", "rules", "previous_forward", "external_firewall"}:
            raise Error("Повреждена конфигурация Cascade v1.")
        state = dict(version=2, rules=state["rules"], backend=None)
    if set(state) != set(empty_state()) or state["version"] != 2 or state["backend"] not in (None, "nft", "legacy"):
        raise Error("Неизвестный формат state.json.")
    if not isinstance(state["rules"], list) or len(state["rules"]) > 1000:
        raise Error("Некорректный список правил (максимум 1000).")
    seen = set()
    for item in state["rules"]:
        if not isinstance(item, dict) or set(item) != {"proto", "listen", "incoming", "target", "outgoing"}:
            raise Error("Повреждено правило в state.json.")
        if rule(**item) != item or key(item) in seen:
            raise Error("Некорректное или повторное правило.")
        seen.add(key(item))
    return state


def load():
    return validate_state(json.loads(STATE.read_text(encoding="utf-8"))) if STATE.exists() else empty_state()


def option(tokens, *names):
    for i, token in enumerate(tokens[:-1]):
        if token in names:
            return tokens[i + 1], i > 0 and tokens[i - 1] == "!"
    return None, False


def tagged(line):
    return option(shlex.split(line), "--comment")[0] == TAG


def parse_save(text):
    chains, rules = {}, []
    for line in text.splitlines():
        if line.startswith(":"):
            name, policy, *_ = line[1:].split()
            chains[name] = policy
        elif line.startswith("-A "):
            rules.append(line)
    return {"chains": chains, "rules": rules}


def owned(table, snapshot):
    names = set(CHAINS[table])
    content = {name: [] for name in names if name in snapshot["chains"]}
    hooks = []
    for line in snapshot["rules"]:
        tokens = shlex.split(line)
        source = tokens[1]
        dest = option(tokens, "-j", "-g")[0]
        if source in names:
            if not tagged(line):
                raise Error(f"Цепочка {source} содержит чужое правило; она не будет изменена.")
            content[source].append(line)
        elif dest in names:
            if not tagged(line):
                raise Error(f"Обнаружена чужая ссылка на {dest}; операция остановлена.")
            hooks.append(line)
    for name, lines in content.items():
        if not lines:
            raise Error(f"Цепочка {name} уже существует без меток Cascade.")
    return {"chains": content, "hooks": hooks}


def desired(table, rules, snapshot):
    if not rules:
        return {"chains": {}, "hooks": []}
    content = {name: [f"-A {name} -m comment --comment {TAG}"] for name in CHAINS[table]}
    for r in rules:
        proto, listen, incoming, target, outgoing = (r[k] for k in ("proto", "listen", "incoming", "target", "outgoing"))
        ct = (f"-m conntrack --ctstate DNAT --ctorigdst {listen} --ctorigdstport {incoming} "
              f"--ctreplsrc {target} --ctreplsrcport {outgoing}")
        comment = f"-m comment --comment {TAG}"
        if table == "nat":
            content["CSCD_DNAT"].append(f"-A CSCD_DNAT -d {listen}/32 -p {proto} --dport {incoming} {comment} -j DNAT --to-destination {target}:{outgoing}")
            content["CSCD_SNAT"].append(f"-A CSCD_SNAT -p {proto} -d {target}/32 --dport {outgoing} {ct} --ctdir ORIGINAL {comment} -j MASQUERADE")
        else:
            content["CSCD_FWD"].append(f"-A CSCD_FWD -p {proto} {ct} {comment} -j ACCEPT")
    if table == "nat":
        hooks = [f"-A PREROUTING -m addrtype --dst-type LOCAL -m comment --comment {TAG} -j CSCD_DNAT",
                 f"-A POSTROUTING -m comment --comment {TAG} -j CSCD_SNAT"]
    else:
        hooks = [f"-A FORWARD -m comment --comment {TAG} -j CSCD_FWD"]
        if "DOCKER-USER" in snapshot["chains"]:
            hooks.append(f"-A DOCKER-USER -m comment --comment {TAG} -j CSCD_FWD")
    return {"chains": content, "hooks": hooks}


def render(table, current, target):
    previous = owned(table, current)
    if not previous["chains"] and not target["chains"]:
        return ""
    lines = ["*" + table]
    for name in target["chains"]:
        # --noflush rebuilds these declared chains only, preserving foreign chains.
        lines.append(f":{name} - [0:0]")
    for name in previous["chains"].keys() - target["chains"].keys():
        lines.append(f"-F {name}")
    for line in previous["hooks"]:
        lines.append("-D" + line[2:])
    for rules in target["chains"].values():
        lines.extend(rules)
    for line in target["hooks"]:
        _, parent, spec = line.split(" ", 2)
        if parent in current["chains"] or parent in ("PREROUTING", "POSTROUTING", "FORWARD"):
            lines.append(f"-I {parent} 1 {spec}")
    for name in previous["chains"].keys() - target["chains"].keys():
        lines.append(f"-X {name}")
    return "\n".join(lines + ["COMMIT", ""])


class Firewall:
    def __init__(self, backend=None):
        version = run(["iptables", "--version"]).stdout
        self.default = "nft" if "nf_tables" in version else "legacy"
        self.backend = backend or self.default
        self.prefix = "iptables-" + self.backend

    def snapshot(self):
        return {t: parse_save(run([self.prefix + "-save", "-t", t]).stdout) for t in CHAINS}

    def restore_table(self, table, target, test=False):
        script = render(table, self.snapshot()[table], target)
        if script:
            cmd = [self.prefix + "-restore", "--wait", "10", "--noflush"]
            run(cmd + (["--test"] if test else []), data=script)

    def apply(self, targets, test=False):
        order = ("filter", "nat") if targets["nat"]["chains"] else ("nat", "filter")
        for table in order:
            self.restore_table(table, targets[table], test)

    def preflight(self):
        if self.backend != self.default:
            raise Error("Системный backend iptables изменён. Верните прежний backend или удалите правила Cascade.")
        other = "iptables-" + ("legacy" if self.backend == "nft" else "nft") + "-save"
        if shutil.which(other, path=SAFE_PATH):
            saved = parse_save(run([other]).stdout)
            if saved["rules"] or any(p == "DROP" for p in saved["chains"].values()):
                raise Error("Одновременно активны iptables-nft и iptables-legacy. Автоматическое смешивание запрещено.")
        for obj in nft_inventory():
            chain = obj.get("chain", {})
            family, table = chain.get("family"), chain.get("table")
            # iptables-nft also creates raw/mangle/security base chains. Docker
            # uses raw PREROUTING even when its userland proxy is disabled.
            standard = {
                "raw": {"prerouting": ("filter", -300)},
                "mangle": {h: ("filter", -150) for h in ("prerouting", "forward", "postrouting")},
                "nat": {"prerouting": ("nat", -100), "postrouting": ("nat", 100)},
                "filter": {"forward": ("filter", 0)},
                "security": {"forward": ("filter", 50)},
            }
            hook = chain.get("hook")
            compatible = (family == "ip" and chain.get("name") == str(hook).upper()
                          and standard.get(table, {}).get(hook) == (chain.get("type"), chain.get("prio")))
            if (family in ("ip", "inet") and hook in ("forward", "prerouting", "postrouting")
                    and table != "cascade_v1" and not compatible):
                raise Error(f"Найден отдельный nftables firewall {family} {table}. Нужна ручная совместная настройка.")


def nft_inventory():
    if not shutil.which("nft", path=SAFE_PATH):
        return []
    return json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]


def old_nft_table():
    objects = nft_inventory()
    if not any(o.get("table", {}).get("family") == "ip" and o["table"].get("name") == "cascade_v1" for o in objects):
        return None
    if not any(o.get("rule", {}).get("family") == "ip" and o["rule"].get("table") == "cascade_v1"
               and o["rule"].get("chain") == "ownership" and o["rule"].get("comment") == "Cascade managed table v1" for o in objects):
        raise Error("Таблица cascade_v1 не имеет метки владельца; автоматическая миграция остановлена.")
    return run(["nft", "list", "table", "ip", "cascade_v1"]).stdout


def local_addresses():
    return {a["local"] for link in json.loads(run(["ip", "-j", "-4", "addr", "show"]).stdout)
            for a in link.get("addr_info", []) if a.get("family") == "inet"}


def detect_listen(target):
    routes = json.loads(run(["ip", "-j", "-4", "route", "get", ipv4(target)]).stdout)
    if not routes or not routes[0].get("prefsrc"):
        raise Error("Не удалось определить локальный IP; задайте --listen.")
    return ipv4(routes[0]["prefsrc"])


def overlaps(address, listen):
    address = address.strip("[]").split("%", 1)[0]
    if address in ("", "*", "0.0.0.0", "::"):
        return True
    try:
        addr = ipaddress.ip_address(address)
        return str(getattr(addr, "ipv4_mapped", None) or addr) == listen
    except ValueError:
        return False


def socket_conflict(item, output):
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            address, sep, value = fields[3].rpartition(":")
            if sep and value == str(item["incoming"]) and overlaps(address, item["listen"]):
                return True
    return False


def docker_bindings():
    if not Path("/var/run/docker.sock").exists():
        return []
    # Explicit local socket: do not follow a remote Docker context.
    docker = ["docker", "--host", "unix:///var/run/docker.sock"]
    ids = run(docker + ["container", "ls", "--all", "--quiet"]).stdout.split()
    containers = []
    for start in range(0, len(ids), 100):
        containers += json.loads(run(docker + ["container", "inspect", *ids[start:start + 100]]).stdout)
    bindings = []
    for container in containers:
        for mapping in (container.get("HostConfig", {}).get("PortBindings"), container.get("NetworkSettings", {}).get("Ports")):
            for name, entries in (mapping or {}).items():
                for entry in entries or []:
                    if entry.get("HostPort", "").isdigit():
                        bindings.append((name.rsplit("/", 1)[-1], entry.get("HostIp", ""), int(entry["HostPort"]), container.get("Name", "container")))
    return bindings


def nat_conflict(item, line):
    tokens = shlex.split(line)
    if tokens[1] in CHAINS["nat"] or option(tokens, "-j")[0] not in ("DNAT", "REDIRECT"):
        return False
    proto, negative = option(tokens, "-p", "--protocol")
    match = proto in (None, "all", "0", item["proto"], "6" if item["proto"] == "tcp" else "17")
    if match == negative:
        return False
    dest, negative = option(tokens, "-d", "--destination")
    if dest:
        try:
            match = ipaddress.IPv4Address(item["listen"]) in ipaddress.IPv4Network(dest, strict=False)
        except ValueError:
            return True
        if match == negative:
            return False
    ports, negative = option(tokens, "--dport", "--dports", "--destination-port", "--destination-ports")
    if ports is None:
        return True
    match = False
    for part in ports.split(","):
        bounds = part.split(":")
        try:
            lo, hi = int(bounds[0] or 0), int(bounds[-1] or 65535)
        except ValueError:
            return True
        match |= lo <= item["incoming"] <= hi
    return match != negative


def check_ports(rules, snapshot):
    if not rules:
        return
    addresses = local_addresses()
    sockets = {proto: run(["ss", "-H", "-ant" if proto == "tcp" else "-anu"]).stdout for proto in {r["proto"] for r in rules}}
    bindings = docker_bindings()
    for item in rules:
        endpoint = f"{item['listen']}:{item['incoming']}/{item['proto']}"
        if item["listen"] not in addresses:
            raise Error("Локальный IPv4 не назначен этому серверу: " + item["listen"])
        if item["target"] in addresses:
            raise Error("Назначение находится на этом же VPS; нужен удалённый сервер.")
        for proto, address, value, name in bindings:
            if proto == item["proto"] and value == item["incoming"] and overlaps(address, item["listen"]):
                raise Error(endpoint + f" зарезервирован Docker-контейнером {name}. Выберите другой входящий порт.")
        if socket_conflict(item, sockets[item["proto"]]):
            raise Error(endpoint + " занят локальным сервисом (возможно SSH/VPN). Выберите другой входящий порт.")
        if any(nat_conflict(item, line) for line in snapshot["nat"]["rules"]):
            raise Error(endpoint + " занят другим DNAT/REDIRECT. Выберите другой входящий порт.")


def purge(item):
    result = run(["conntrack", "-D", "-p", item["proto"], "--orig-dst", item["listen"],
                  "--orig-port-dst", str(item["incoming"]), "--reply-src", item["target"],
                  "--reply-port-src", str(item["outgoing"])], ok=(0, 1))
    if result.returncode == 1 and "0 flow entries have been deleted" not in result.stderr:
        raise Error(result.stderr.strip() or "Ошибка удаления conntrack.")


def stage(state):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".state-", dir=STATE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return Path(name)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def transition(old, new, *, save=True, check=True):
    new = copy.deepcopy(new)
    fw = Firewall(old["backend"])
    snapshot = fw.snapshot()
    backup = {t: owned(t, snapshot[t]) for t in CHAINS}
    legacy = old_nft_table()
    if new["rules"] and check:
        fw.preflight()
        check_ports(new["rules"], snapshot)
    targets = {t: desired(t, new["rules"], snapshot[t]) for t in CHAINS}
    new["backend"] = fw.backend
    validate_state(new)
    pending = stage(new) if save else None
    changed = False
    removed_legacy = False
    try:
        fw.apply(targets, test=True)
        if new["rules"] and FORWARD.read_text().strip() != "1":
            FORWARD.write_text("1\n")
        changed = True
        fw.apply(targets)
        if legacy:
            run(["nft", "delete", "table", "ip", "cascade_v1"])
            removed_legacy = True
        if pending:
            os.replace(pending, STATE)
    except BaseException as error:
        if changed:
            try:
                fw.apply(backup)
                if removed_legacy:
                    run(["nft", "-f", "-"], data=legacy)
            except BaseException as rollback:
                raise Error(f"Ошибка: {error}; откат тоже не удался: {rollback}. Выполните cascade apply.") from error
        raise
    finally:
        if pending:
            pending.unlink(missing_ok=True)
    # Forwarding is shared with Docker/VPNs. Never disable it, even on rollback.
    failures = []
    for item in old["rules"]:
        if item not in new["rules"]:
            try:
                purge(item)
            except (Error, subprocess.SubprocessError) as exc:
                failures.append(str(exc))
    if failures:
        raise Error("Правила удалены, но старые соединения не очищены: " + "; ".join(failures))


@contextlib.contextmanager
def locked():
    import fcntl
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE.parent / ".lock", "a", encoding="utf-8") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def display(state):
    for n, item in enumerate(state["rules"], 1):
        print(f"{n}. {item['proto']} {item['listen']}:{item['incoming']} -> {item['target']}:{item['outgoing']}")
    if not state["rules"]:
        print("Правил Cascade нет.")


def execute(args):
    with locked():
        old = load()
        new = copy.deepcopy(old)
        if args.command == "list":
            display(old)
            return
        if args.command == "status":
            display(old)
            print("ip_forward=" + FORWARD.read_text().strip())
            fw = Firewall(old["backend"])
            print("Backend: " + fw.prefix)
            for table, snapshot in fw.snapshot().items():
                for name in owned(table, snapshot)["chains"]:
                    print(run([fw.prefix, "-w", "10", "-t", table, "-nvL", name]).stdout)
            return
        if args.command == "apply":
            transition(old, old)
        elif args.command == "stop":
            new["rules"] = []
            transition(old, new, save=False, check=False)
        elif args.command == "add":
            incoming = port(args.in_port)
            outgoing = port(args.out_port) if args.out_port is not None else incoming
            target = ipv4(args.target)
            listen = args.listen or detect_listen(target)
            item = rule(args.proto, listen, incoming, target, outgoing)
            existing = next((r for r in old["rules"] if key(r) == key(item)), None)
            if existing and existing != item and not args.replace:
                raise Error("Этот входящий адрес/порт занят правилом Cascade. Для замены укажите --replace.")
            new["rules"] = [r for r in new["rules"] if key(r) != key(item)] + [item]
            transition(old, new)
        elif args.command == "delete":
            wanted = (args.proto, ipv4(args.listen), port(args.in_port))
            new["rules"] = [r for r in old["rules"] if key(r) != wanted]
            transition(old, new, check=False)
        elif args.command == "clear":
            new["rules"] = []
            transition(old, new, check=False)
        print("Готово.")


def parser():
    root = argparse.ArgumentParser(description="Cascade — каскадный IPv4 TCP/UDP relay")
    root.add_argument("--version", action="version", version=VERSION)
    sub = root.add_subparsers(dest="command")
    for name in ("list", "status", "apply", "stop", "menu"):
        sub.add_parser(name)
    add = sub.add_parser("add")
    add.add_argument("--proto", required=True, choices=("tcp", "udp"))
    add.add_argument("--listen", help="Локальный IPv4; по умолчанию адрес маршрута к цели")
    add.add_argument("--in-port", required=True)
    add.add_argument("--target", required=True)
    add.add_argument("--out-port")
    add.add_argument("--replace", action="store_true")
    delete = sub.add_parser("delete")
    delete.add_argument("--proto", required=True, choices=("tcp", "udp"))
    delete.add_argument("--listen", required=True)
    delete.add_argument("--in-port", required=True)
    clear = sub.add_parser("clear")
    clear.add_argument("--yes", required=True, action="store_true")
    return root


def ask(label, validate):
    while True:
        value = input(label).strip()
        try:
            validate(value)
            return value
        except Error as exc:
            print("Ошибка: " + str(exc))


def menu():
    while True:
        print("\nCascade\n1) AmneziaWG / WireGuard (UDP)\n2) VLESS / XRay (TCP)\n"
              "3) MTProto (TCP)\n4) Произвольные TCP/UDP порты\n5) Список\n"
              "6) Удалить правило\n7) Удалить все правила Cascade\n8) Инструкция\n0) Выход")
        choice = input("> ").strip()
        try:
            if choice == "0":
                return
            if choice in ("1", "2", "3", "4"):
                proto = input("Протокол tcp/udp: ").strip() if choice == "4" else "udp" if choice == "1" else "tcp"
                if proto not in ("tcp", "udp"):
                    raise Error("Введите tcp или udp.")
                target = ask("IPv4 назначения: ", ipv4)
                listen = input("Локальный IPv4 (Enter — определить автоматически): ").strip() or detect_listen(target)
                def validate_incoming(value):
                    item = rule(proto, listen, value, target, value)
                    with locked():
                        state = load()
                        if any(key(r) == key(item) for r in state["rules"]):
                            raise Error("Этот входящий порт уже используется Cascade.")
                        check_ports([item], Firewall(state["backend"]).snapshot())
                incoming = ask("Входящий порт: ", validate_incoming)
                outgoing = ask("Порт назначения: ", port) if choice == "4" else incoming
                execute(parser().parse_args(["add", "--proto", proto, "--target", target, "--listen", listen,
                                             "--in-port", incoming, "--out-port", outgoing]))
            elif choice == "5":
                execute(parser().parse_args(["status"]))
            elif choice == "6":
                with locked():
                    state = load()
                    display(state)
                    if not state["rules"]:
                        continue
                    value = input("Номер правила (0 — отмена): ").strip()
                    if value == "0":
                        continue
                    if not value.isdecimal() or not 1 <= int(value) <= len(state["rules"]):
                        raise Error("Неверный номер правила.")
                    new = copy.deepcopy(state)
                    del new["rules"][int(value) - 1]
                    transition(state, new, check=False)
                    print("Готово.")
            elif choice == "7" and input("Удалить только правила Cascade? [yes]: ") == "yes":
                execute(parser().parse_args(["clear", "--yes"]))
            elif choice == "8":
                print("Создайте правило на промежуточном VPS. В клиенте замените endpoint на публичный IP этого "
                      "VPS и входящий порт. Ключи, UUID и TLS/SNI остаются от конечного VPN. "
                      "Другие сервисы должны использовать другие входящие порты. "
                      "Документация: https://github.com/WeirdPhrog/Cascade")
        except (Error, OSError, ValueError, subprocess.SubprocessError) as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)


def main():
    args = parser().parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Error("Нужен Linux и запуск через sudo/root.")
    os.umask(0o077)
    os.environ["PATH"] = SAFE_PATH
    if args.command in (None, "menu"):
        if not sys.stdin.isatty():
            raise Error("Для меню нужен терминал; для автоматизации используйте cascade --help.")
        menu()
    else:
        execute(args)


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        sys.exit(130)
