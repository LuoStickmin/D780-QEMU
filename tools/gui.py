#!/usr/bin/env python3
"""D780-QEMU boot monitor GUI.

A small, dependency-free web UI in the spirit of the z6-qemu browser
controller.  It does not render a framebuffer (D780 has no LCD model yet);
it starts the nikon-d780 machine, follows the QEMU log and exposes live boot
state (SVCs, exceptions, probe events, last PCs) with start/stop/restart.

Usage (WSL/Linux):
    python3 tools/gui.py --payload /path/to/eg1510_012100.bi \
        --qemu /path/to/qemu-system-arm [--port 8787]
    # open http://127.0.0.1:8787/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RUNS = Path(os.environ.get("D780_GUI_RUNS") or (Path(tempfile.gettempdir()) / "d780-gui"))

TB_RE = re.compile(r"^0x([0-9a-fA-F]{8}):")
EXC_RE = re.compile(r"Taking exception (\d)")
PROBE_RE = re.compile(r"^d750-probe:")
PROBE_ADDR_RE = re.compile(r"addr=0x([0-9a-fA-F]+)")

SVC_RE = re.compile(r"^d750-svc:")

STAGES = [
    (0x10020000, 0x10030000, "startup / page tables"),
    (0x10030000, 0x10080000, "MMU + early init"),
    (0x10080000, 0x10100000, "kernel init"),
    (0x10100000, 0x10108000, "exception vectors"),
    (0x10108000, 0x10120000, "kernel / drivers"),
    (0x10120000, 0x10200000, "peripherals / scheduler"),
    (0x10200000, 0x11000000, "post-init code"),
]

MACHINE_EXTRAS = "e6-prep=on"


def stage_for(pc: int | None) -> str:
    if pc is None:
        return "not started"
    for lo, hi, name in STAGES:
        if lo <= pc < hi:
            return name
    return "unknown (0x%08x)" % pc


class Monitor:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.run_dir: Path | None = None
        self.log_path: Path | None = None
        self.uart_path: Path | None = None
        self.started_at: float | None = None
        self.offset = 0
        self.svc = 0
        self.undef = 0
        self.prefetch = 0
        self.data_abort = 0
        self.probe = 0
        self.last_probe = ""
        self.tb = 0
        self.pcs: list[int] = []
        self.log_tail: list[str] = []
        self.last_error = ""

    # -- process control ---------------------------------------------------
    def start(self) -> dict:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return {"ok": False, "error": "already running"}
            payload = Path(self.args.payload)
            if not payload.is_file():
                return {"ok": False, "error": "payload not found: %s" % payload}
            qemu = self.args.qemu
            if not qemu:
                qemu = os.environ.get("D780_QEMU", "qemu-system-arm")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            self.run_dir = RUNS / ("gui-" + stamp)
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self.log_path = self.run_dir / "qemu.log"
            self.uart_path = self.run_dir / "uart.log"
            machine = "nikon-d780"
            if MACHINE_EXTRAS:
                machine += "," + MACHINE_EXTRAS
            cmd = [
                qemu,
                "-M", machine,
                "-cpu", self.args.cpu,
                "-m", self.args.ram,
                "-smp", str(self.args.smp),
                "-display", "none",
                "-monitor", "none",
                "-serial", "file:" + str(self.uart_path),
                "-D", str(self.log_path),
                "-d", "int,in_asm,guest_errors",
                "-no-reboot",
                "-nic", "none",
                "-kernel", str(payload),
            ]
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
            except FileNotFoundError:
                return {"ok": False, "error": "qemu not found: %s" % qemu}
            self.started_at = time.time()
            self.offset = 0
            self.svc = self.undef = self.prefetch = self.data_abort = 0
            self.probe = self.tb = 0
            self.pcs = []
            self.log_tail = []
            self.last_error = ""
            return {"ok": True, "pid": self.proc.pid}

    def stop(self) -> dict:
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                return {"ok": False, "error": "not running"}
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            return {"ok": True}

    def restart(self) -> dict:
        self.stop()
        time.sleep(0.3)
        return self.start()

    # -- log parsing -------------------------------------------------------
    def poll(self) -> None:
        with self.lock:
            if not self.log_path or not self.log_path.exists():
                return
            try:
                with self.log_path.open("rb") as f:
                    f.seek(self.offset)
                    chunk = f.read(1 << 20)
                    self.offset += len(chunk)
            except OSError as exc:
                self.last_error = str(exc)
                return
            if not chunk:
                return
            for raw in chunk.decode("utf-8", "replace").splitlines():
                m = EXC_RE.search(raw)
                if m:
                    n = int(m.group(1))
                    if n == 1:
                        self.undef += 1
                    elif n == 2:
                        self.svc += 1
                    elif n == 3:
                        self.prefetch += 1
                    elif n == 4:
                        self.data_abort += 1
                    continue
                if PROBE_RE.search(raw):
                    self.probe += 1
                    m = PROBE_ADDR_RE.search(raw)
                    if m:
                        self.last_probe = m.group(1)
                    continue
                m = TB_RE.match(raw)
                if m:
                    self.tb += 1
                    pc = int(m.group(1), 16)
                    self.pcs.append(pc)
                    if len(self.pcs) > 16:
                        self.pcs.pop(0)
                self.log_tail.append(raw)
                if len(self.log_tail) > 120:
                    self.log_tail.pop(0)

    def status(self) -> dict:
        self.poll()
        with self.lock:
            running = bool(self.proc and self.proc.poll() is None)
            elapsed = time.time() - self.started_at if self.started_at else 0.0
            return {
                "running": running,
                "pid": self.proc.pid if self.proc else None,
                "elapsed": round(elapsed, 1),
                "svc": self.svc,
                "undef": self.undef,
                "prefetch": self.prefetch,
                "data": self.data_abort,
                "probe": self.probe,
                "last_probe": self.last_probe or None,
                "tb": self.tb,
                "last_pc": "0x%08x" % self.pcs[-1] if self.pcs else None,
                "pcs": ["0x%08x" % p for p in self.pcs[-8:]],
                "stage": stage_for(self.pcs[-1] if self.pcs else None),
                "cpu": self.args.cpu,
                "smp": self.args.smp,
                "payload": Path(self.args.payload).name,
                "run_dir": str(self.run_dir) if self.run_dir else None,
                "log": self.log_tail[-60:],
                "error": self.last_error,
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "D780GUI/1.0"
    monitor: Monitor = None  # set in main()

    def log_message(self, *a):
        return

    def _send(self, code: int, body: bytes, ctype: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = (HERE / "gui.html").read_bytes()
            self._send(200, html, "text/html; charset=utf-8")
        elif self.path.startswith("/api/status"):
            self._json(self.monitor.status())
        elif self.path.startswith("/api/log"):
            st = self.monitor.status()
            self._send(200, "\n".join(st["log"]).encode(), "text/plain; charset=utf-8")
        elif self.path == "/favicon.ico":
            self._send(204, b"")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path == "/api/start":
            self._json(self.monitor.start())
        elif self.path == "/api/stop":
            self._json(self.monitor.stop())
        elif self.path == "/api/restart":
            self._json(self.monitor.restart())
        else:
            self._json({"ok": False, "error": "unknown endpoint"}, 404)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--payload", required=True, help="decrypted D780 eg1510 image")
    p.add_argument("--qemu", default="", help="qemu-system-arm path (or D780_QEMU)")
    p.add_argument("--cpu", default="cortex-a15")
    p.add_argument("--ram", default="128M")
    p.add_argument("--smp", type=int, default=2)
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--bind", default="127.0.0.1")
    a = p.parse_args()

    mon = Monitor(a)
    Handler.monitor = mon
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    url = "http://%s:%d/" % (a.bind, a.port)
    print("D780 boot monitor: %s" % url, flush=True)
    print("payload: %s" % a.payload, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        mon.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
