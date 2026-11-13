#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Трещотка размеров исходников LAVRay Core (Rust).

Правила (паритет со стандартами Linux-сборки):
  * новый файл (нет в baseline) — не длиннее 200 строк;
  * существующий файл — не растёт относительно baseline.

Использование:
  python scripts/size_ratchet.py            # проверка
  python scripts/size_ratchet.py --write-baseline  # пересобрать baseline
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "size-ratchet.json"
NEW_FILE_LIMIT = 200
EXTS = {".rs"}
SKIP_DIRS = {"target", ".git", "node_modules"}


def source_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def line_count(path):
    return len(path.read_text(encoding="utf-8").splitlines())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    current = {
        str(p.relative_to(ROOT)).replace("\\", "/"): line_count(p)
        for p in source_files()
    }

    if args.write_baseline:
        BASELINE.write_text(
            json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"baseline записан: {len(current)} файлов")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}
    violations = []
    for path, count in current.items():
        if path not in baseline:
            if count > NEW_FILE_LIMIT:
                violations.append(f"{path}: {count} строк, новый файл не длиннее {NEW_FILE_LIMIT}")
        elif count > baseline[path]:
            violations.append(
                f"{path}: {count} строк, в baseline {baseline[path]}. "
                "Большой файл не растёт: новую логику вынесите в новый файл"
            )

    for v in violations:
        print(f"нарушение: {v}")
    print(f"size_ratchet: проверено {len(current)} файлов, нарушений: {len(violations)}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
