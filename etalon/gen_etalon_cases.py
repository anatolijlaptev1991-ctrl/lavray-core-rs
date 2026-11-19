#!/usr/bin/env python3
"""Генератор эталонных кейсов rust-anything для lavray-core-rs.

Каждый кейс — самодостаточный (файлы внутри "files"), запускается
в песочнице trycmd. Перед записью каждый кейс прогоняется через
эталонный Go-бинарь sing-box 1.14.1-neko.1 для локальной сверки
ожидаемого exit-кода (валидные = 0, невалидные = 1).

Выход: etalon/inputs.jsonl для `rust-anything app record`.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ETALON = Path(r"D:\ZCode\nekobox\_deps\sing-box-etalon.exe")
OUT = Path(__file__).parent / "inputs.jsonl"

# --- конфиги (мини, без внешних .srs — песочница самодостаточна) ---

MIXED_DIRECT = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}

SS2022 = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 8388,
            "method": "2022-blake3-aes-128-gcm",
            "password": "aaaaaaaaaaaaaaaaaaaaaa==",
        },
        {"type": "direct", "tag": "direct"},
    ],
}

VMESS_WS_TLS = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "vmess",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "security": "auto",
            "transport": {"type": "ws", "path": "/vl", "headers": {"Host": "example.com"}},
            "tls": {"enabled": True, "server_name": "example.com", "insecure": False},
        },
        {"type": "direct", "tag": "direct"},
    ],
}

VLESS_REALITY = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "vless",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "www.microsoft.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    "short_id": "0123456789abcdef",
                },
            },
        },
        {"type": "direct", "tag": "direct"},
    ],
}

TROJAN = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "trojan",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 443,
            "password": "pass1234",
            "tls": {"enabled": True, "server_name": "example.com"},
        },
        {"type": "direct", "tag": "direct"},
    ],
}

HY2 = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "hysteria2",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 443,
            "password": "pass1234",
            "tls": {"enabled": True, "server_name": "example.com"},
        },
        {"type": "direct", "tag": "direct"},
    ],
}

TUIC = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "tuic",
            "tag": "proxy",
            "server": "192.0.2.1",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "pass1234",
            "congestion_control": "bbr",
            "tls": {"enabled": True, "server_name": "example.com"},
        },
        {"type": "direct", "tag": "direct"},
    ],
}

DNS_ADVANCED = {
    "dns": {
        "servers": [
            {"tag": "dns-remote", "type": "https", "server": "dns.google", "detour": "proxy"},
            {"tag": "dns-direct", "type": "local"},
        ],
        "rules": [
            {"clash_mode": "Direct", "server": "dns-direct"},
        ],
        "final": "dns-remote",
        "strategy": "prefer_ipv4",
    },
    "route": {"final": "proxy", "auto_detect_interface": True, "default_domain_resolver": "dns-direct"},
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "direct", "tag": "proxy"}, {"type": "direct", "tag": "direct"}],
}

ROUTE_INLINE = {
    "route": {
        "rules": [
            {"protocol": "dns", "action": "hijack-dns"},
            {"domain_suffix": [".cn"], "outbound": "direct"},
            {"ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"], "outbound": "direct"},
            {"process_name": ["game.exe"], "outbound": "direct"},
            {"domain_keyword": ["ads"], "action": "reject"},
        ],
        "final": "proxy",
        "auto_detect_interface": True,
    },
    "inbounds": [
        {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}
    ],
    "outbounds": [{"type": "direct", "tag": "proxy"}, {"type": "direct", "tag": "direct"}],
}

GROUPS = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto", "direct"],
            "default": "auto",
            "interrupt_exist_connections": False,
        },
        {"type": "urltest", "tag": "auto", "outbounds": ["a"], "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
        {"type": "shadowsocks", "tag": "a", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "pw"},
        {"type": "direct", "tag": "direct"},
    ],
}

TUN_IN = {
    "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "mtu": 9000, "auto_route": True}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}

EMPTY_OBJ = {}
UNKNOWN_TOP = dict(MIXED_DIRECT, unknown_top_level=True)
UNKNOWN_OUT_TYPE = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "no-such-protocol", "tag": "x"}],
}
BAD_PORT_STR = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": "2080"}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}
BAD_VMESS_UUID = {
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [
        {"type": "vmess", "tag": "p", "server": "192.0.2.1", "server_port": 443, "uuid": "not-a-uuid"},
        {"type": "direct", "tag": "direct"},
    ],
}
BAD_STRATEGY = {
    "dns": {"servers": [{"tag": "dns-direct", "type": "local"}], "strategy": "prefer_ipvx"},
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}
DUP_TAG = {
    "inbounds": [
        {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080},
        {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2081},
    ],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}
ROUTE_MISSING_OUTBOUND = {
    "route": {"rules": [{"domain_suffix": [".cn"], "outbound": "no-such-outbound"}], "final": "proxy"},
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "direct", "tag": "proxy"}],
}
RULESET_MISSING_FILE = {
    "route": {"rules": [{"rule_set": ["ghost"], "outbound": "direct"}], "rule_set": [{"type": "local", "tag": "ghost", "format": "source", "path": "ghost.json"}]},
    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}

# --- rule-set (source JSON) для match/compile/format ---

RS_DOMAINS = {
    "version": 3,
    "rules": [
        {"domain": ["accounts.google.com", "www.google.com"]},
        {"domain_suffix": [".googleapis.com", ".doubleclick.net"]},
        {"domain_keyword": ["gemini"]},
        {"domain_regex": ["^ads-[0-9]+\\.example\\.com$"]},
    ],
}
RS_IPS = {"version": 3, "rules": [{"ip_cidr": ["10.0.0.0/8", "192.168.1.0/24"]}]}
RS_PROCESS = {"version": 3, "rules": [{"process_name": ["telegram.exe", "game.bin"]}]}


def cfg(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


CASES = []


def add(name, args, files=None, expect_ok=None):
    CASES.append({"name": name, "args": args, "files": files or {}, "_expect_ok": expect_ok})


# A. check — валидные
for nm, obj in [
    ("check-mixed-direct", MIXED_DIRECT),
    ("check-ss-2022", SS2022),
    ("check-vmess-ws-tls", VMESS_WS_TLS),
    ("check-vless-reality", VLESS_REALITY),
    ("check-trojan", TROJAN),
    ("check-hysteria2", HY2),
    ("check-tuic", TUIC),
    ("check-dns-advanced", DNS_ADVANCED),
    ("check-route-inline", ROUTE_INLINE),
    ("check-groups", GROUPS),
    ("check-tun", TUN_IN),
]:
    add(nm, ["check", "-c", "config.json"], {"config.json": cfg(obj)}, expect_ok=True)

# B. check — невалидные (error paths)
add("check-broken-json", ["check", "-c", "bad.json"], {"bad.json": "{ not json"}, expect_ok=False)
# sing-box 1.14: пустой объект-конфиг ВАЛИДЕН (всё дефолт)
add("check-empty-object", ["check", "-c", "config.json"], {"config.json": cfg(EMPTY_OBJ)}, expect_ok=True)
add("check-unknown-top-field", ["check", "-c", "config.json"], {"config.json": cfg(UNKNOWN_TOP)}, expect_ok=False)
add("check-unknown-outbound-type", ["check", "-c", "config.json"], {"config.json": cfg(UNKNOWN_OUT_TYPE)}, expect_ok=False)
add("check-port-as-string", ["check", "-c", "config.json"], {"config.json": cfg(BAD_PORT_STR)}, expect_ok=False)
# sing-box 1.14: невалидный uuid vmess принимается check-ем (парсится свободно)
add("check-bad-vmess-uuid", ["check", "-c", "config.json"], {"config.json": cfg(BAD_VMESS_UUID)}, expect_ok=True)
add("check-bad-dns-strategy", ["check", "-c", "config.json"], {"config.json": cfg(BAD_STRATEGY)}, expect_ok=False)
add("check-duplicate-tag", ["check", "-c", "config.json"], {"config.json": cfg(DUP_TAG)}, expect_ok=False)
# sing-box 1.14: ссылка правила на несуществующий outbound НЕ ловится check-ем (runtime-only)
add("check-rule-out-missing-outbound", ["check", "-c", "config.json"], {"config.json": cfg(ROUTE_MISSING_OUTBOUND)}, expect_ok=True)
add("check-ruleset-missing-file", ["check", "-c", "config.json"], {"config.json": cfg(RULESET_MISSING_FILE)}, expect_ok=False)
add("check-missing-config-file", ["check", "-c", "ghost.json"], expect_ok=False)

# C. format
add("format-dirty-json", ["format", "-c", "config.json"], {"config.json": json.dumps(MIXED_DIRECT) + "\n\n  "}, expect_ok=True)

# D. rule-set: match (source JSON) + compile + format
rs_files = {"rs.json": cfg(RS_DOMAINS), "rs-ips.json": cfg(RS_IPS), "rs-proc.json": cfg(RS_PROCESS)}
add("rs-match-domain-hit", ["rule-set", "match", "rs.json", "www.google.com"], rs_files, expect_ok=True)
add("rs-match-domain-suffix", ["rule-set", "match", "rs.json", "api.googleapis.com"], rs_files, expect_ok=True)
add("rs-match-keyword", ["rule-set", "match", "rs.json", "gemini.google.com"], rs_files, expect_ok=True)
add("rs-match-regex-hit", ["rule-set", "match", "rs.json", "ads-42.example.com"], rs_files, expect_ok=True)
add("rs-match-miss", ["rule-set", "match", "rs.json", "example.org"], rs_files, expect_ok=True)
add("rs-match-ip-cidr", ["rule-set", "match", "rs-ips.json", "10.1.2.3"], rs_files, expect_ok=True)
# match различает попадание только stdout; exit=0 и при промахе
add("rs-match-ip-miss", ["rule-set", "match", "rs-ips.json", "8.8.8.8"], rs_files, expect_ok=True)
add("rs-match-ip-as-domain-arg", ["rule-set", "match", "rs.json", "8.8.8.8"], rs_files, expect_ok=True)
add("rs-match-process", ["rule-set", "match", "rs-proc.json", "telegram.exe"], rs_files, expect_ok=True)
add("rs-compile-domains", ["rule-set", "compile", "rs.json", "-o", "out.srs"], rs_files, expect_ok=True)
add("rs-format-source", ["rule-set", "format", "rs.json"], rs_files, expect_ok=True)

# E. CLI-контракт
add("version", ["version"], expect_ok=True)
add("help-root", ["help"], expect_ok=True)
add("unknown-command", ["no-such-command"], expect_ok=False)
add("check-no-args", ["check"], expect_ok=False)


def run_case(case) -> int:
    """Прогон кейса через эталон в отдельном временном каталоге. Возврат exit-кода."""
    with tempfile.TemporaryDirectory() as td:
        for rel, text in case["files"].items():
            p = Path(td) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        r = subprocess.run([str(ETALON), *case["args"]], cwd=td, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        return r.returncode


def main() -> int:
    bad = 0
    with OUT.open("w", encoding="utf-8") as fh:
        for c in CASES:
            code = run_case(c)
            ok = (code == 0) == bool(c["_expect_ok"])
            status = "OK " if ok else "MISMATCH"
            if not ok:
                bad += 1
            print(f"[{status}] {c['name']}: exit={code} expect_ok={c['_expect_ok']}")
            row = {k: v for k, v in c.items() if not k.startswith("_")}
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"\n{len(CASES)} cases -> {OUT} ({bad} mismatched expectations)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
