#!/usr/bin/python3 -I
"""Cascade: an IPv4 TCP/UDP relay with an owned, atomic nftables table."""
import argparse
import contextlib
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

VERSION = "1.0.0"
TABLE = "cascade_v1"
OWNER = "Cascade managed table v1"
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
        raise Error("Нужен IPv4-адрес, без DNS-имени или параметров команд.") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
        raise Error("Нужен unicast IPv4-адрес, отличный от loopback/0.0.0.0.")
    return str(address)


def port(value):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,5}", str(value)):
        raise Error("Порт должен быть целым числом 1–65535.")
    value = int(value)
    if not 1 <= value <= 65535:
        raise Error("Порт должен быть целым числом 1–65535.")
    return value


def rule(proto, listen, incoming, target, outgoing):
    if proto not in ("tcp", "udp"):
        raise Error("Поддерживаются только tcp и udp.")
    result = dict(proto=proto, listen=ipv4(listen), incoming=port(incoming),
                  target=ipv4(target), outgoing=port(outgoing))
    if result["listen"] == result["target"]:
        raise Error("Адрес назначения должен отличаться от адреса этого сервера.")
    return result


def key(item):
    return item["proto"], item["listen"], item["incoming"]


def empty_state():
    return {"version": 1, "rules": [], "previous_forward": None, "external_firewall": False}


def validate_state(state):
    if not isinstance(state, dict) or set(state) != set(empty_state()) or state["version"] != 1:
        raise Error("Неизвестный формат state.json.")
    if type(state["external_firewall"]) is not bool or state["previous_forward"] not in (None, "0", "1"):
        raise Error("Повреждён state.json.")
    if not isinstance(state["rules"], list) or len(state["rules"]) > 1000:
        raise Error("Некорректный список правил (максимум 1000).")
    seen = set()
    for item in state["rules"]:
        if not isinstance(item, dict) or set(item) != {"proto", "listen", "incoming", "target", "outgoing"}:
            raise Error("Повреждено правило в state.json.")
        if rule(**item) != item or key(item) in seen:
            raise Error("Некорректное или повторное правило в state.json.")
        seen.add(key(item))
    if state["rules"] and state["previous_forward"] is None:
        raise Error("Не сохранено исходное значение ip_forward.")
    return state


def load():
    if not STATE.exists():
        return empty_state()
    return validate_state(json.loads(STATE.read_text(encoding="utf-8")))


def inventory():
    return json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]


def owns_table(objects):
    for obj in objects:
        table = obj.get("table", {})
        if table.get("family") == "ip" and table.get("name") == TABLE:
            if table.get("comment") != OWNER:
                raise Error(f"Таблица ip {TABLE} уже существует и не принадлежит Cascade.")
            return True
    return False


def check_firewall(objects, allow):
    conflicts = []
    for obj in objects:
        chain = obj.get("chain", {})
        if chain.get("family") in ("ip", "inet") and chain.get("table") != TABLE and chain.get("hook") == "forward":
            conflicts.append(f"{chain['family']} {chain['table']} {chain['name']}")
    if shutil.which("iptables-legacy-save", path=SAFE_PATH):
        saved = run(["iptables-legacy-save", "-t", "filter"]).stdout
        if ":FORWARD DROP" in saved or "-A FORWARD " in saved:
            conflicts.append("iptables-legacy FORWARD")
    if conflicts and not allow:
        raise Error("Обнаружен сторонний FORWARD firewall: " + ", ".join(conflicts) +
                    ". Сначала разрешите пересылку в нём; затем используйте --external-firewall (см. README).")


def render(rules, exists):
    lines = [f"delete table ip {TABLE}"] if exists else []
    if not rules:
        return "\n".join(lines) + ("\n" if lines else "")
    lines += [f"table ip {TABLE} {{", f' comment "{OWNER}"',
              " chain prerouting {", "  type nat hook prerouting priority dstnat; policy accept;"]
    for r in rules:
        lines.append(f"  ip daddr {r['listen']} {r['proto']} dport {r['incoming']} counter dnat to {r['target']}:{r['outgoing']}")
    lines += [" }", " chain postrouting {", "  type nat hook postrouting priority srcnat; policy accept;"]
    for r in rules:
        lines.append(f"  ct status dnat ct original ip daddr {r['listen']} ct original proto-dst {r['incoming']} "
                     f"ip daddr {r['target']} {r['proto']} dport {r['outgoing']} counter masquerade")
    lines += [" }", "}"]
    return "\n".join(lines) + "\n"


def apply(rules):
    script = render(rules, owns_table(inventory()))
    if script:
        run(["nft", "--check", "-f", "-"], data=script)
        # A single netlink batch: deleting and replacing our table is atomic.
        run(["nft", "-f", "-"], data=script)


def local_addresses():
    return {a["local"] for link in json.loads(run(["ip", "-j", "-4", "addr", "show"]).stdout)
            for a in link.get("addr_info", []) if a.get("family") == "inet"}


def detect_listen(target):
    routes = json.loads(run(["ip", "-j", "-4", "route", "get", ipv4(target)]).stdout)
    if not routes or not routes[0].get("prefsrc"):
        raise Error("Не удалось определить локальный IP; задайте --listen.")
    return ipv4(routes[0]["prefsrc"])


def check_listener(item, allow_local):
    if item["listen"] not in local_addresses():
        raise Error("--listen должен быть IPv4-адресом сетевого интерфейса этого сервера.")
    if item["target"] in local_addresses():
        raise Error("Назначение находится на этом сервере; нужен удалённый сервер.")
    listeners = run(["ss", "-H", "-lnt" if item["proto"] == "tcp" else "-lnu"]).stdout
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] == str(item["incoming"]) and not allow_local:
            raise Error("Входящий порт занят локальным сервисом (возможно SSH). Выберите другой порт "
                        "или явно укажите --allow-local-port.")


def purge(item):
    result = run(["conntrack", "-D", "-p", item["proto"], "--orig-dst", item["listen"],
                  "--orig-port-dst", str(item["incoming"]), "--reply-src", item["target"],
                  "--reply-port-src", str(item["outgoing"])], ok=(0, 1))
    # conntrack returns 1 for an empty match as well as some genuine errors.
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


def transition(old, new):
    new = copy.deepcopy(new)
    before = FORWARD.read_text().strip()
    if new["rules"]:
        if not old["rules"]:
            new["previous_forward"] = before
        if any(item not in old["rules"] for item in new["rules"]):
            check_firewall(inventory(), new["external_firewall"])
    desired = "1" if new["rules"] else old["previous_forward"] or before
    if not new["rules"]:
        new["previous_forward"] = None
    validate_state(new)
    pending = stage(new)
    try:
        # Validate the kernel transaction before changing the global forwarding bit.
        script = render(new["rules"], owns_table(inventory()))
        if script:
            run(["nft", "--check", "-f", "-"], data=script)
        if before != desired:
            FORWARD.write_text(desired + "\n")
        apply(new["rules"])
        os.replace(pending, STATE)
    except BaseException as error:
        try:
            apply(old["rules"])
            if FORWARD.read_text().strip() != before:
                FORWARD.write_text(before + "\n")
        except BaseException as rollback:
            raise Error(f"Ошибка: {error}; откат тоже не удался: {rollback}. Выполните cascade apply.") from error
        raise
    finally:
        pending.unlink(missing_ok=True)
    failures = []
    for item in old["rules"]:
        if item not in new["rules"]:
            try:
                purge(item)
            except Error as exc:
                failures.append(str(exc))
    if failures:
        raise Error("Правила сохранены, но старые соединения не очищены: " + "; ".join(failures))


def restore(state):
    if state["rules"]:
        check_firewall(inventory(), state["external_firewall"])
        script = render(state["rules"], owns_table(inventory()))
        run(["nft", "--check", "-f", "-"], data=script)
        before = FORWARD.read_text().strip()
        FORWARD.write_text("1\n")
        try:
            apply(state["rules"])
        except BaseException:
            FORWARD.write_text(before + "\n")
            raise
    else:
        apply([])


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
            if owns_table(inventory()):
                print(run(["nft", "list", "table", "ip", TABLE]).stdout)
            else:
                print("Таблица Cascade не загружена.")
            return
        if args.command == "apply":
            restore(old)
        elif args.command == "stop":
            apply([])
            for item in old["rules"]:
                purge(item)
            if old["previous_forward"] is not None:
                FORWARD.write_text(old["previous_forward"] + "\n")
        elif args.command == "add":
            listen = args.listen or detect_listen(args.target)
            item = rule(args.proto, listen, args.in_port, args.target, args.out_port or args.in_port)
            check_listener(item, args.allow_local_port)
            existing = next((r for r in old["rules"] if key(r) == key(item)), None)
            if existing and existing != item and not args.replace:
                raise Error("Этот входящий адрес/порт уже занят правилом. Для замены укажите --replace.")
            new["rules"] = [r for r in new["rules"] if key(r) != key(item)] + [item]
            new["external_firewall"] = args.external_firewall or old["external_firewall"]
            transition(old, new)
        elif args.command == "delete":
            wanted = (args.proto, ipv4(args.listen), port(args.in_port))
            new["rules"] = [r for r in old["rules"] if key(r) != wanted]
            transition(old, new)
        elif args.command == "clear":
            new["rules"] = []
            transition(old, new)
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
    add.add_argument("--allow-local-port", action="store_true")
    add.add_argument("--external-firewall", action="store_true")
    delete = sub.add_parser("delete")
    delete.add_argument("--proto", required=True, choices=("tcp", "udp"))
    delete.add_argument("--listen", required=True)
    delete.add_argument("--in-port", required=True)
    clear = sub.add_parser("clear")
    clear.add_argument("--yes", required=True, action="store_true")
    return root


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
                target = input("IPv4 назначения: ").strip()
                incoming = input("Входящий порт: ").strip()
                outgoing = input("Порт назначения: ").strip() if choice == "4" else incoming
                listen = input("Локальный IPv4 (Enter — определить автоматически): ").strip()
                argv = ["add", "--proto", proto, "--target", target, "--in-port", incoming, "--out-port", outgoing]
                if listen:
                    argv += ["--listen", listen]
                execute(parser().parse_args(argv))
            elif choice == "5":
                execute(parser().parse_args(["status"]))
            elif choice == "6":
                execute(parser().parse_args(["list"]))
                proto = input("Протокол: ").strip()
                listen = input("Локальный IPv4: ").strip()
                incoming = input("Входящий порт: ").strip()
                execute(parser().parse_args(["delete", "--proto", proto, "--listen", listen, "--in-port", incoming]))
            elif choice == "7" and input("Удалить только правила Cascade? [yes]: ") == "yes":
                execute(parser().parse_args(["clear", "--yes"]))
            elif choice == "8":
                print("Создайте правило на промежуточном VPS. В клиенте замените адрес/порт endpoint на публичный "
                      "IP этого VPS и входящий порт. Ключи, UUID и TLS/SNI остаются от конечного VPN. "
                      "Это NAT relay; VPN-сервер и шифрование он не устанавливает. Документация: "
                      "https://github.com/WeirdPhrog/Cascade")
        except (Error, ValueError) as exc:
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
