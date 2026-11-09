# SPDX-License-Identifier: GPL-2.0-or-later
"""Apply the Nikon D780 (E6) validation overlay to a QEMU source tree.

The overlay is deliberately small: one board file plus one header.  It does
not vendor or patch upstream QEMU code.  Re-running is idempotent.

QEMU 11.1 renamed the chardev frontend type ``CharBackend`` to
``CharFrontend``; for 10.x trees the copied board file is rewritten to the
old spelling so the same overlay builds on both generations.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

OVERLAY_VERSION = "1.0"
SUPPORTED = {"10.2.4", "11.1.0"}

MESON_DESC = ("{var}.add(when: 'CONFIG_NIKON_D780_LAB', "
              "if_true: files('nikon-d780-lab.c'))\n")
KCONFIG_BLOCK = """
config NIKON_D780_LAB
    bool
    depends on TCG && ARM

"""
MAK_LINE = "\nCONFIG_NIKON_D780_LAB=y\n"


def _meson_line(version: str) -> str:
    # QEMU 11 renamed the board source set from arm_ss to arm_common_ss.
    var = "arm_common_ss" if version.startswith("11.") else "arm_ss"
    return MESON_DESC.format(var=var)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ensure_line(path: Path, line: str) -> bool:
    text = _read(path)
    if line.strip() in text:
        return False
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text + line, encoding="utf-8")
    return True


def _ensure_meson(path: Path, version: str) -> bool:
    original = _read(path)
    text = re.sub(r"(?m)^.*CONFIG_NIKON_D780_LAB.*\n", "", original)
    if not text.endswith("\n"):
        text += "\n"
    text += _meson_line(version)
    if text == original:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def _ensure_kconfig(path: Path) -> bool:
    text = _read(path)
    if KCONFIG_BLOCK.strip() in text:
        return False
    stripped = re.sub(r"\nconfig NIKON_D780_LAB\n(?:[ \t].*\n)*", "\n", text)
    if not stripped.endswith("\n"):
        stripped += "\n"
    path.write_text(stripped + KCONFIG_BLOCK, encoding="utf-8")
    return True


def _write_if_changed(path: Path, content: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def prepare(root: Path, project: Path | None = None,
            allow_unsupported: bool = False) -> dict:
    """Copy the overlay into *root* and register it.

    Returns a JSON-serialisable summary.  Raises SystemExit with a clear
    message on an unexpected tree.
    """
    root = Path(root).resolve()
    project = Path(project or Path(__file__).resolve().parent).resolve()
    version_file = root / "VERSION"
    if not version_file.is_file():
        raise SystemExit(f"not a QEMU source tree (no VERSION): {root}")
    version = version_file.read_text(encoding="utf-8").strip()
    if version not in SUPPORTED and not allow_unsupported:
        raise SystemExit(
            f"QEMU {version} is not a pinned target for this overlay; "
            f"supported: {', '.join(sorted(SUPPORTED))}. "
            "Use --allow-unsupported to try anyway."
        )

    board = _read(project / "nikon-d780-lab.c")
    header = _read(project / "nikon-d780-lab.h")
    if version.startswith("10."):
        board = board.replace("CharFrontend", "CharBackend")

    dest = root / "hw" / "arm"
    if not dest.is_dir():
        raise SystemExit(f"unexpected QEMU tree: {dest} is missing")

    changed = {}
    if _write_if_changed(dest / "nikon-d780-lab.c", board):
        changed["hw/arm/nikon-d780-lab.c"] = "written"
    if _write_if_changed(dest / "nikon-d780-lab.h", header):
        changed["hw/arm/nikon-d780-lab.h"] = "written"
    if _ensure_meson(root / "hw" / "arm" / "meson.build", version):
        changed["hw/arm/meson.build"] = "appended"
    if _ensure_kconfig(root / "hw" / "arm" / "Kconfig"):
        changed["hw/arm/Kconfig"] = "appended"
    if _ensure_line(root / "configs" / "devices" / "arm-softmmu" / "default.mak",
                    MAK_LINE):
        changed["configs/devices/arm-softmmu/default.mak"] = "appended"

    return {
        "overlay_version": OVERLAY_VERSION,
        "qemu_version": version,
        "root": str(root),
        "changed": changed,
        "chardev_type": "CharBackend" if version.startswith("10.") else "CharFrontend",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="QEMU source tree")
    parser.add_argument("--allow-unsupported", action="store_true")
    args = parser.parse_args(argv)
    summary = prepare(args.root, allow_unsupported=args.allow_unsupported)
    print(f"Prepared QEMU {summary['qemu_version']} at {summary['root']}")
    for name, action in summary["changed"].items():
        print(f"  {action:9s} {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
