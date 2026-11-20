#!/usr/bin/env python3
"""Replay записанных app-cases против НАШЕГО бинаря (lavray-core).

Прогоняет подмножество кейсов `rust/app-cases/` (команды, поддерживаемые
портом: check / format / rule-set) в песочнице каждого кейса и сверяет
stdout/stderr/exit-код с записью Go-эталона. Абсолютные пути песочницы
нормализуются в [CWD] (как делает rust-anything при записи).

Использование: python -I etalon/replay_port.py [--bin target/debug/lavray-core.exe]
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "rust" / "app-cases"
SUPPORTED = ("check", "format", "rule-set", "version", "help", "no-such-command")


def main() -> int:
    bin_path = ROOT / "target/debug/lavray-core.exe"
    if "--bin" in sys.argv:
        bin_path = Path(sys.argv[sys.argv.index("--bin") + 1])
    passed = failed = skipped = 0
    fails = []
    for toml in sorted(CASES.glob("*.toml")):
        name = toml.stem
        body = toml.read_text(encoding="utf-8")
        args = json.loads(
            re.search(r"args = (\[.*\])", body).group(1).replace("'", '"')
        )
        if not args or args[0] not in SUPPORTED:
            skipped += 1
            continue
        files = {}
        indir = CASES / f"{name}.in"
        if indir.exists():
            for f in indir.rglob("*"):
                if f.is_file():
                    files[str(f.relative_to(indir))] = f.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as td:
            for rel, text in files.items():
                (Path(td) / rel).write_text(text, encoding="utf-8")
            r = subprocess.run(
                [str(bin_path), *args],
                cwd=td,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            want_out = (CASES / f"{name}.stdout").read_text(encoding="utf-8")
            want_err = (CASES / f"{name}.stderr").read_text(encoding="utf-8")
            want_code = int(re.search(r"status.code = (\d+)", body).group(1))
            norm = lambda s, td=td: s.replace(td, "[CWD]").replace("\\", "/")
            ok = (
                r.stdout == want_out
                and norm(r.stderr) == norm(want_err)
                and r.returncode == want_code
            )
            if ok:
                passed += 1
            else:
                failed += 1
                fails.append(
                    (
                        name,
                        f"got(code={r.returncode}, err={norm(r.stderr)[:110]!r}, out={norm(r.stdout)[:60]!r}) "
                        f"want(code={want_code}, err={norm(want_err)[:110]!r})",
                    )
                )
    print(f"REPLAY: PASS={passed} FAIL={failed} (skipped {skipped} cobra/CLI-кейсов)")
    for n, d in fails[:10]:
        print("==", n)
        print("  ", d)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
