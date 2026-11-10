# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the Nikon D750 validation prototype and record evidence.

The launcher never modifies the firmware.  It maps it, starts the CPU at the
profile entry, optionally attaches the RSP client for a checkpoint snapshot,
and always leaves a session directory with the exact command, the guest
serial bytes, the QEMU diagnostic log and a parsed MMIO summary.

Examples:
    python tools/run.py --payload D750_0115.dec.modules/b1010_115a.bin \
        --flash D750_0115.dec.modules/a1010_011100.bin --timeout 10

    python tools/run.py --payload ... --gdb --run-seconds 3 \
        --checkpoint 0x9025D720
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
DEFAULT_ENTRY = 0x10020000
BOOT_STUB = 0x9025D700
DEFAULT_BOOT = "entry"
DEFAULT_A1010_BASE = 0x10018000
DEFAULT_CPU = "cortex-a15"

PROBE_RE = re.compile(
    r"d750-(?P<src>probe|a1010-io): pc=(?P<pc>0x[0-9a-f]+) "
    r"(?P<rw>rd|wr) addr=(?P<addr>0x[0-9a-f]+) size=(?P<size>\d+)"
    r"(?: value=(?P<value>0x[0-9a-f]+))?"
)
UART_RE = re.compile(r"d750-uart: pc=(0x[0-9a-f]+) rd \+0x([0-9a-f]+) size=(\d+) -> (0x[0-9a-f]+)")
HALT_RE = re.compile(
    r"d750-halt: pc=(0x[0-9a-f]+) r0=(0x[0-9a-f]+) r1=(0x[0-9a-f]+)"
    r" sp=(0x[0-9a-f]+) lr=(0x[0-9a-f]+)"
    r"(?: return_ok=(true|false) mode=(0x[0-9a-f]+))?"
)
STRICT_RE = re.compile(
    r"d750-strict: pc=(0x[0-9a-f]+) (rd|wr) addr=(0x[0-9a-f]+) size=(\d+)"
    r"(?: value=(0x[0-9a-f]+))?"
)
LCD_RE = re.compile(
    r"d750-lcd: dumped (\d+)x(\d+) \(([^,]+), stride (\d+)\)"
    r" from (0x[0-9a-f]+) to (.+)"
)


def find_qemu(explicit: str | None = None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("D750_QEMU")
    if env:
        candidates.append(Path(env))
    for pattern in (
        ".build/build/qemu-system-arm.exe",
        ".build/build/qemu-system-arm",
        ".build/src/*/build/qemu-system-arm.exe",
        ".build/src/*/build/qemu-system-arm",
    ):
        candidates.extend(sorted(PROJECT.glob(pattern)))
    candidates.append(Path(r"C:\Program Files\qemu\qemu-system-arm.exe"))
    found = shutil.which("qemu-system-arm")
    if found:
        candidates.append(Path(found))
    for cand in candidates:
        if cand and Path(cand).is_file():
            return Path(cand)
    return None


def machine_supported(qemu: Path) -> tuple[bool, str]:
    try:
        out = subprocess.run([str(qemu), "-M", "help"], capture_output=True,
                             text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return ("nikon-d780" in out.stdout), out.stdout


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def sha256_file(path: Path) -> str | None:
    """SHA-256 of a firmware input, or None when the file is absent."""
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize_probe_log(path: Path) -> dict:
    events = []
    if not path.is_file():
        return {"events": 0, "a1010_events": 0, "first_a1010": None,
                "by_address": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in PROBE_RE.finditer(text):
        events.append({
            "source": "a1010" if match.group("src") == "a1010-io" else "probe",
            "pc": match.group("pc"),
            "rw": match.group("rw"),
            "addr": match.group("addr"),
            "size": int(match.group("size")),
            "value": match.group("value") or "0x00000000",
        })
    counts: dict[tuple[str, str], dict] = {}
    for ev in events:
        key = (ev["addr"], ev["rw"])
        rec = counts.setdefault(key, {"addr": ev["addr"], "rw": ev["rw"],
                                      "count": 0, "first_pc": ev["pc"],
                                      "size": ev["size"]})
        rec["count"] += 1
    by_addr = sorted(counts.values(), key=lambda r: r["count"], reverse=True)
    a1010_events = [ev for ev in events if ev["source"] == "a1010"]
    return {
        "events": len(events),
        "a1010_events": len(a1010_events),
        "first_a1010": a1010_events[0] if a1010_events else None,
        "by_address": by_addr[:50],
    }


def summarize_uart(path: Path, tail: int = 4096) -> dict:
    if not path.is_file():
        return {"bytes": 0, "tail": ""}
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "tail": data[-tail:].decode("utf-8", errors="replace"),
    }


def summarize_halt(path: Path) -> dict | None:
    """Parse the assisted-return record written by the halt window."""
    if not path.is_file():
        return None
    match = HALT_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    if not match:
        return None
    return_ok = None
    if match.group(6) is not None:
        return_ok = match.group(6) == "true"
    return {
        "pc": match.group(1), "r0": match.group(2), "r1": match.group(3),
        "sp": match.group(4), "lr": match.group(5),
        "return_ok": return_ok, "mode": match.group(7),
        # Old (v0.1.0) binaries did not record return_ok; only an explicit
        # false makes the halt suspicious.
        "suspicious": return_ok is False,
    }


def summarize_strict(path: Path) -> dict | None:
    """Parse the first strict-mode stop record (d750-strict:)."""
    if not path.is_file():
        return None
    match = STRICT_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    if not match:
        return None
    return {
        "pc": match.group(1), "rw": match.group(2), "addr": match.group(3),
        "size": int(match.group(4)), "value": match.group(5) or "0x00000000",
    }


def summarize_lcd(path: Path) -> dict | None:
    """Parse the last framebuffer dump record."""
    if not path.is_file():
        return None
    matches = LCD_RE.findall(path.read_text(encoding="utf-8", errors="replace"))
    if not matches:
        return None
    width, height, fmt, stride, base, out = matches[-1]
    return {
        "width": int(width), "height": int(height), "format": fmt.strip(),
        "stride": int(stride), "base": base, "out": out.strip(),
    }


def build_command(qemu: Path, args: argparse.Namespace, run_dir: Path,
                  gdb_port: int | None) -> list[str]:
    machine = "nikon-d780"
    machine += f",boot-mode={args.boot}"
    if args.boot == "entry" and args.entry is not None:
        machine += f",entry=0x{args.entry:x}"
    if args.a1010_base is not None:
        machine += f",a1010-base=0x{args.a1010_base:x}"
    if args.payload_base is not None:
        machine += f",payload-base=0x{args.payload_base:x}"
    if not args.thumb_fix:
        machine += ",thumb-fix=off"
    if not args.mmu_bringup:
        machine += ",mmu-bringup=off"
    if args.mpcore_base is not None:
        machine += f",mpcore-base=0x{args.mpcore_base:x}"
    if args.flash_size is not None:
        machine += f",flash-size=0x{args.flash_size:x}"
    if args.aux_ram_size:
        machine += f",aux-ram-size=0x{args.aux_ram_size:x}"
    if args.aux2_size:
        machine += (f",aux2-base=0x{args.aux2_base:x}"
                    f",aux2-size=0x{args.aux2_size:x}")
    if args.mmu_table is not None:
        machine += f",mmu-table=0x{args.mmu_table:x}"
    if args.vector_fix:
        machine += ",vector-fix=on"
    if args.veneer_slot is not None:
        machine += f",veneer-slot=0x{args.veneer_slot:x}"
    if args.loader_copies:
        machine += ",loader-copies=on"
    if args.io_stub:
        machine += ",io-stub=on"
    if args.e6_prep:
        machine += ",e6-prep=on"
    if args.strict:
        machine += ",strict=on"
    if args.lcd_base is not None:
        machine += (f",lcd-base=0x{args.lcd_base:x}"
                    f",lcd-width={args.lcd_width}"
                    f",lcd-height={args.lcd_height}"
                    f",lcd-stride={args.lcd_stride}"
                    f",lcd-format={args.lcd_format}")
        if args.lcd_out:
            machine += f",lcd-out={Path(args.lcd_out).as_posix()}"
    debug = ",".join(["guest_errors", *args.trace])
    cmd = [
        str(qemu), "-M", machine,
        "-cpu", args.cpu,
        "-m", args.ram,
        "-smp", str(args.smp),
        "-display", "none",
        "-monitor", "none",
        "-serial", "file:" + str(run_dir / "uart.log").replace("\\", "/"),
        "-D", str(run_dir / "qemu.log"),
        "-d", debug,
        "-no-reboot",
        "-nic", "none",
        "-kernel", str(Path(args.payload).resolve()),
    ]
    if args.flash:
        cmd += ["-bios", str(Path(args.flash).resolve())]
    if gdb_port is not None:
        cmd += ["-S", "-gdb", f"tcp:127.0.0.1:{gdb_port}"]
    return cmd


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def gdb_snapshot(port: int, entry: int, checkpoint: int | None,
                 run_seconds: float) -> dict:
    sys.path.insert(0, str(PROJECT / "tools"))
    from probe import RSPClient  # noqa: PLC0415

    client = RSPClient("127.0.0.1", port)
    result: dict = {"stop": None}
    try:
        regs = client.read_registers()
        result["entry_pc"] = f"0x{regs.get('pc', 0):08x}"
        result["entry_ok"] = regs.get("pc") == entry
        result["cpsr"] = f"0x{regs.get('cpsr', 0):08x}"
        try:
            if checkpoint is not None:
                client.set_breakpoint(checkpoint)
            stop = client.continue_(run_seconds)
            result["stop"] = {"kind": stop.kind, "signal": stop.signal,
                              "thread": stop.thread, "raw": stop.raw}
            regs = client.read_registers()
            result["pc"] = f"0x{regs.get('pc', 0):08x}"
            result["registers"] = {k: f"0x{v:08x}" for k, v in regs.items()}
            if checkpoint is not None:
                result["checkpoint_hit"] = regs.get("pc") == checkpoint
        except Exception as exc:  # noqa: BLE001
            # A self-shutdown (halt window) closes the RSP socket while the
            # guest is running; record that as a normal post-run outcome.
            result["stop"] = {"kind": "connection-closed", "raw": str(exc)}
            result["guest_exited"] = True
    finally:
        client.close()
    return result


def parse_size(text: str) -> int:
    """Parse a size with an optional K/M/G suffix (e.g. 4M, 0x1400000)."""
    t = str(text).strip().lower()
    mult = 1
    for suffix, value in (("g", 1 << 30), ("m", 1 << 20), ("k", 1 << 10)):
        if t.endswith(suffix):
            mult = value
            t = t[:-1]
            break
    return int(t, 0) * mult


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--payload", required=True,
                        help="decrypted main module (b1010_*.bin)")
    parser.add_argument("--flash", help="decrypted flash/first-stage module (a1010_*.bin)")
    parser.add_argument("--qemu", help="qemu-system-arm binary")
    parser.add_argument("--cpu", default=DEFAULT_CPU)
    parser.add_argument("--ram", default="128M")
    parser.add_argument("--smp", type=int, default=2,
                        help="CPU count (D780 needs 2; one CPU waits at 0x1011C014)")
    parser.add_argument("--boot", choices=("stub", "entry"), default=DEFAULT_BOOT,
                        help="startup mode: 'stub' runs the b1010 boot chain and "
                             "hands off to a1010 (M1, default); 'entry' starts at "
                             "--entry directly (M0)")
    parser.add_argument("--entry", type=lambda s: int(s, 0),
                        help=f"initial PC for --boot entry (default 0x{DEFAULT_ENTRY:x})")
    parser.add_argument("--a1010-base", type=lambda s: int(s, 0),
                        default=DEFAULT_A1010_BASE,
                        help="address the a1010 module is mapped at "
                             f"(default 0x{DEFAULT_A1010_BASE:x})")
    parser.add_argument("--payload-base", type=lambda s: int(s, 0),
                        help="address the b1010 image is loaded at; the "
                             "NikonHacker IDA scripts use 0x90020000")
    parser.add_argument("--thumb-fix", dest="thumb_fix", action="store_true",
                        default=True,
                        help="patch the bx literal to 0x1002CB8D (default)")
    parser.add_argument("--no-thumb-fix", dest="thumb_fix", action="store_false",
                        help="leave the firmware literal untouched (a1010 will "
                             "be entered in ARM state)")
    parser.add_argument("--mmu-bringup", dest="mmu_bringup",
                        action="store_true", default=True,
                        help="supply the boot ROM's identity page table and "
                             "TTBR0/DACR before the stub enables the MMU "
                             "(default)")
    parser.add_argument("--no-mmu-bringup", dest="mmu_bringup",
                        action="store_false",
                        help="start directly at the stub (expected to fault when "
                             "the stub enables the MMU)")
    parser.add_argument("--mpcore-base", type=lambda s: int(s, 0),
                        help="override the MPCore/GIC base (diagnostics; default "
                             "0xE000E000)")
    parser.add_argument("--flash-size", type=parse_size,
                        help="flash window size (e.g. 20M or 0x1400000); "
                             "default is the machine's 8M")
    parser.add_argument("--aux-ram-size", type=parse_size, default=0,
                        help="add a RAM bank at 0x20000000 (e.g. 4M; default 0)")
    parser.add_argument("--aux2-base", type=lambda s: int(s, 0),
                        default=0x40000000,
                        help="handler-RAM base for --aux2-size (default 0x40000000)")
    parser.add_argument("--aux2-size", type=parse_size, default=0,
                        help="add a handler RAM bank at --aux2-base (e.g. 2M)")
    parser.add_argument("--mmu-table", type=lambda s: int(s, 0),
                        help="place the identity table at this address and leave "
                             "config slot 0x100F48C0 to the flash image")
    parser.add_argument("--vector-fix", action="store_true", default=False,
                        help="install a minimal ARM vector table at 0x90020000")
    parser.add_argument("--veneer-slot", type=lambda s: int(s, 0),
                        help="payload offset of one ldr-pc veneer target to "
                             "mark as Thumb (e.g. 0x14e494)")
    parser.add_argument("--loader-copies", action="store_true", default=False,
                        help="apply the descriptor-table flash-to-RAM copies to "
                             "the in-memory payload before boot")
    parser.add_argument("--io-stub", action="store_true", default=False,
                        help="map the A2/AD/AE/A340 register blocks as a "
                             "register file and report 0xAE00060C ready")
    parser.add_argument("--e6-prep", action="store_true", default=False,
                        help="D780 prep: identity-section the page table at "
                             "payload+0x10000 and map boot SRAM/stacks")
    parser.add_argument("--trace", action="append", default=[],
                        help="extra -d item, e.g. --trace in_asm (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="stop at the first unmodelled MMIO access "
                             "(logs d750-strict: and exits)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="run time in seconds (non-GDB mode)")
    parser.add_argument("--gdb", action="store_true",
                        help="start paused and take an RSP snapshot")
    parser.add_argument("--run-seconds", type=float, default=3.0)
    parser.add_argument("--checkpoint", type=lambda s: int(s, 0),
                        help="run until this PC (GDB mode)")
    parser.add_argument("--lcd-base", type=lambda s: int(s, 0),
                        help="optional framebuffer base for a PPM dump")
    parser.add_argument("--lcd-width", type=int, default=640)
    parser.add_argument("--lcd-height", type=int, default=480)
    parser.add_argument("--lcd-stride", type=int, default=0)
    parser.add_argument("--lcd-format", default="argb8888",
                        choices=("argb8888", "rgb888", "rgb565"))
    parser.add_argument("--lcd-out", help="PPM path (default <run>/lcd.ppm)")
    parser.add_argument("--out", type=Path,
                        help="session directory (default runs/<timestamp>)")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    entry = args.entry if args.entry is not None else DEFAULT_ENTRY
    start = BOOT_STUB if args.boot == "stub" else entry
    # The machine may start at its internal MMU trampoline (0x1000) and only
    # then branch to the stub; the session still reports the architectural
    # entry (0x9025D700), while GDB expects the actual first PC.
    expected_pc = (0x1000 if args.boot == "stub" and args.mmu_bringup
                   else start)
    qemu = find_qemu(args.qemu)
    if qemu is None:
        print("error: qemu-system-arm not found; pass --qemu or build the "
              "overlay (see docs/build.md)", file=sys.stderr)
        return 2
    supported, machines = machine_supported(qemu)
    if not supported:
        print(f"error: {qemu} has no 'nikon-d780' machine.", file=sys.stderr)
        print("This is expected for a stock QEMU build. Build the overlay "
              "first (docs/build.md); the installed stock binary cannot load "
              "a new machine at runtime.", file=sys.stderr)
        return 3

    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = args.out or (PROJECT / "runs" / stamp)
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    if args.lcd_base is not None and not args.lcd_out:
        args.lcd_out = str(run_dir / "lcd.ppm")

    port = free_port() if args.gdb else None
    cmd = build_command(qemu, args, run_dir, port)
    (run_dir / "command.json").write_text(json.dumps({
        "argv": cmd, "entry": f"0x{start:08x}", "gdb": bool(args.gdb),
    }, indent=2) + "\n", encoding="utf-8")
    if args.dry_run:
        print(" ".join(cmd))
        return 0

    payload_path = Path(args.payload).resolve()
    flash_path = Path(args.flash).resolve() if args.flash else None
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    session: dict = {
        "argv": cmd,
        "entry": f"0x{start:08x}",
        "payload": str(payload_path),
        "payload_sha256": sha256_file(payload_path),
        "payload_size": payload_path.stat().st_size if payload_path.is_file() else None,
        "flash": str(flash_path) if flash_path else None,
        "flash_sha256": sha256_file(flash_path) if flash_path else None,
        "flash_size": (flash_path.stat().st_size
                       if flash_path and flash_path.is_file() else None),
        "started": _dt.datetime.now().isoformat(timespec="seconds"),
    }

    if args.gdb:
        if not wait_for_port(port or 0):
            out = proc.stdout.read() if proc.stdout else ""
            session["error"] = "gdbstub did not open"
            session["qemu_output"] = out[-4000:]
            print(json.dumps(session, indent=2))
            proc.terminate()
            return 4
        try:
            session["snapshot"] = gdb_snapshot(port or 0, expected_pc,
                                               args.checkpoint, args.run_seconds)
        except Exception as exc:  # noqa: BLE001 - record, do not hide
            session["error"] = f"{type(exc).__name__}: {exc}"
        stop_timeout = 5.0
    else:
        stop_timeout = args.timeout

    try:
        proc.wait(timeout=stop_timeout)
        session["exit"] = proc.returncode
        session["timed_out"] = False
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        session["exit"] = proc.returncode
        session["timed_out"] = True

    session["wall_seconds"] = round(time.time() - started, 3)
    session["qemu_output_tail"] = (proc.stdout.read()[-4000:]
                                   if proc.stdout else "")
    session["uart"] = summarize_uart(run_dir / "uart.log")
    session["mmio"] = summarize_probe_log(run_dir / "qemu.log")
    session["halt"] = summarize_halt(run_dir / "qemu.log")
    session["lcd"] = summarize_lcd(run_dir / "qemu.log")
    session["strict"] = summarize_strict(run_dir / "qemu.log")

    if session["timed_out"]:
        status = "timeout"
    elif session["strict"] is not None:
        status = "strict-stop"
    elif session["halt"] and session["halt"]["suspicious"]:
        status = "halt-suspicious"
    elif session["halt"] is not None:
        status = "halt"
    elif session["exit"] == 0:
        status = "ran"
    else:
        status = f"exit-{session['exit']}"
    session["status"] = status

    (run_dir / "session.json").write_text(json.dumps(session, indent=2) + "\n",
                                          encoding="utf-8")

    print(f"session: {run_dir}")
    print(f"status={status}  entry 0x{start:08x}  exit={session['exit']}  "
          f"timed_out={session['timed_out']}  uart={session['uart']['bytes']}B  "
          f"mmio_events={session['mmio']['events']}  "
          f"a1010_io={session['mmio']['a1010_events']}")
    if session["halt"]:
        halt = session["halt"]
        print(f"halt: pc={halt['pc']} r0={halt['r0']} r1={halt['r1']} "
              f"sp={halt['sp']} lr={halt['lr']} return_ok={halt['return_ok']}")
    if session["strict"]:
        stop = session["strict"]
        print(f"strict: {stop['rw']} {stop['addr']} size={stop['size']} "
              f"(pc {stop['pc']})")
    if session["lcd"]:
        lcd = session["lcd"]
        print(f"lcd: {lcd['width']}x{lcd['height']} {lcd['format']} "
              f"@ {lcd['base']} -> {lcd['out']}")
    if args.gdb:
        snap = session.get("snapshot", {})
        print(f"pc={snap.get('pc')}  checkpoint_hit={snap.get('checkpoint_hit')}  "
              f"stop={snap.get('stop')}")
        if not snap.get("pc") and snap.get("guest_exited"):
            print("gdb: guest exited before a register snapshot (halt recorded)")
    if session["uart"]["tail"]:
        print("uart tail:")
        print(session["uart"]["tail"][-1200:])
    first_a1010 = session["mmio"].get("first_a1010")
    if first_a1010:
        print(f"first a1010 MMIO: {first_a1010['rw']} {first_a1010['addr']} "
              f"size={first_a1010['size']} at pc {first_a1010['pc']}")
    if session["mmio"]["by_address"]:
        print("top unmodelled MMIO:")
        for rec in session["mmio"]["by_address"][:10]:
            print(f"  {rec['rw']} {rec['addr']} x{rec['count']} (first pc {rec['first_pc']})")

    if status == "strict-stop":
        print("stopped at the first unmodelled access (exit code 7); "
              "model this access before re-running M1/M2")
        return 7
    if status == "halt-suspicious":
        print("warning: the trampoline was reached from an unexpected state "
              "(return_ok=false); this is not a clean entry return (exit code 6)")
        return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
