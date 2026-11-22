#!/usr/bin/env python3
"""
SecureMed-IoT PRESENT-80 — Web Demo UI
Flask backend using Server-Sent Events (SSE) for live terminal streaming.
Zero external JS dependencies — everything served locally.
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import math
import json
import random

from flask import Flask, render_template, request, jsonify, Response, stream_with_context, send_from_directory

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_DIR   = os.path.join(PROJECT_ROOT, "python")
STATIC_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
sys.path.insert(0, PYTHON_DIR)

app = Flask(__name__)
app.config["SECRET_KEY"] = "securemed-iot-demo-2024"

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(STATIC_DIR, "favicon.ico", mimetype="image/vnd.microsoft.icon")

# Active SSE queues: stream_id -> Queue
_streams: dict[str, queue.Queue] = {}
_streams_lock = threading.Lock()


# ─── SSE helpers ────────────────────────────────────────────────────────────

def _new_stream() -> tuple[str, queue.Queue]:
    sid = str(random.randint(100000, 999999))
    q: queue.Queue = queue.Queue()
    with _streams_lock:
        _streams[sid] = q
    return sid, q


def _push(sid: str, event: str, data: str):
    with _streams_lock:
        q = _streams.get(sid)
    if q:
        q.put(f"event: {event}\ndata: {data}\n\n")


def _close(sid: str):
    with _streams_lock:
        q = _streams.pop(sid, None)
    if q:
        q.put(None)   # sentinel


def stream_command(cmd: str, sid: str, cwd: str | None = None):
    cwd = cwd or PROJECT_ROOT
    _push(sid, "line", json.dumps({"line": f"<span class='cmd'>$ {cmd}</span>"}))
    try:
        proc = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for raw in proc.stdout:
            _push(sid, "line", json.dumps({"line": raw.rstrip()}))
        proc.wait()
        ok = proc.returncode == 0
        msg = f"{'✓ Done' if ok else '✗ Failed'} (exit {proc.returncode})"
        cls = "success" if ok else "error"
        _push(sid, "line",  json.dumps({"line": f"<span class='{cls}'>{msg}</span>"}))
        _push(sid, "done",  json.dumps({"returncode": proc.returncode}))
    except Exception as exc:
        _push(sid, "line", json.dumps({"line": f"<span class='error'>ERROR: {exc}</span>"}))
        _push(sid, "done", json.dumps({"returncode": -1}))
    finally:
        _close(sid)


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/run", methods=["POST"])
def api_run():
    """Start a subprocess stream. Returns {sid} to subscribe to /api/stream/<sid>."""
    step = request.json.get("step", "")
    cmds = {
        "unit_tests":     'python3 -m unittest discover -s tests -p "test_*.py" -v',
        "cipher_core":    "python3 python/present.py",
        "data_integrity": "python3 python/data_integrity.py",
        "benchmarks":     "python3 python/benchmark.py",
        "telemetry": (
            "python3 python/simulate_sensor_node.py --count 6 --out /tmp/sensor_stream.txt && "
            "python3 python/decrypt_host.py --file /tmp/sensor_stream.txt"
        ),
        "tamper": (
            "python3 python/simulate_sensor_node.py --count 6 --tamper --out /tmp/sensor_tampered.txt && "
            "python3 python/decrypt_host.py --file /tmp/sensor_tampered.txt"
        ),
        "attacks":   "cd python && python3 attack_simulation.py",
        "native_c": (
            "gcc -O2 tests/test_c_native.c arduino/present_cipher.c -Iarduino "
            "-o tests/test_c_native && ./tests/test_c_native"
        ),
    }
    cmd = cmds.get(step)
    if not cmd:
        return jsonify({"error": f"Unknown step: {step}"}), 400

    sid, _ = _new_stream()
    threading.Thread(target=stream_command, args=(cmd, sid, PROJECT_ROOT), daemon=True).start()
    return jsonify({"sid": sid})


@app.route("/api/stream/<sid>")
def api_stream(sid):
    """SSE endpoint: streams events for the given stream id."""
    with _streams_lock:
        q = _streams.get(sid)
    if not q:
        return Response("data: stream not found\n\n", mimetype="text/event-stream")

    def generate():
        while True:
            try:
                chunk = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if chunk is None:
                break
            yield chunk

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/sensor_live")
def sensor_live():
    from present import PRESENT
    KEY_HEX = "0123456789ABCDEF0123"
    key     = bytes.fromhex(KEY_HEX)
    cipher  = PRESENT(key)
    count   = int(request.args.get("count", 10))
    tamper  = request.args.get("tamper", "false").lower() == "true"

    packets = []
    for i in range(count):
        t_ms     = (i + 1) * 200
        ts_field = t_ms & 0xFFFF
        phase    = (i % 5) / 5.0
        if phase == 0.4:
            ecg_val = 3200
        elif phase == 0.2:
            ecg_val = 1600
        else:
            ecg_val = int(2048 + 400 * math.sin(i * 0.8))

        hr_val    = 72 + int(4 * math.sin(i * 0.5))
        plaintext = (ecg_val << 32) | (hr_val << 16) | ts_field
        ct        = cipher.encrypt(plaintext)

        is_tampered = tamper and (i == 4)
        if is_tampered:
            ct ^= 0x0000000100000000

        pt_dec  = cipher.decrypt(ct)
        ecg_dec = (pt_dec >> 32) & 0xFFFFFFFF
        hr_dec  = (pt_dec >> 16) & 0xFFFF
        valid   = (40 <= hr_dec <= 200) and (0 <= ecg_dec <= 4095)

        packets.append({
            "packet":     i + 1,
            "time_ms":    t_ms,
            "ecg_raw":    ecg_val,
            "heart_rate": hr_val,
            "plaintext":  f"0x{plaintext:016X}",
            "ciphertext": f"0x{ct:016X}",
            "tampered":   is_tampered,
            "ecg_dec":    ecg_dec,
            "hr_dec":     hr_dec,
            "valid":      valid,
        })

    return jsonify({"key": KEY_HEX, "packets": packets})


@app.route("/api/encrypt")
def api_encrypt():
    from present import PRESENT
    pt_hex  = request.args.get("plaintext", "0000000000000000")
    key_hex = request.args.get("key", "0123456789ABCDEF0123")
    try:
        pt  = int(pt_hex, 16)
        key = bytes.fromhex(key_hex)
        c   = PRESENT(key)
        ct  = c.encrypt(pt)
        pt2 = c.decrypt(ct)
        return jsonify({
            "plaintext":  f"{pt:016X}",
            "key":        key_hex.upper(),
            "ciphertext": f"{ct:016X}",
            "roundtrip":  f"{pt2:016X}",
            "match":      pt == pt2,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/benchmark_quick")
def api_benchmark_quick():
    import time as _t
    from present import PRESENT
    n   = int(request.args.get("n", 3000))
    key = os.urandom(10)
    c   = PRESENT(key)
    pt  = random.getrandbits(64)
    for _ in range(30):
        c.encrypt(pt)
    t0 = _t.perf_counter()
    blk = pt
    for _ in range(n):
        blk = c.encrypt(blk)
    enc_el = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    for _ in range(n):
        blk = c.decrypt(blk)
    dec_el = _t.perf_counter() - t0
    return jsonify({
        "n":              n,
        "enc_avg_us":     round((enc_el / n) * 1e6, 3),
        "dec_avg_us":     round((dec_el / n) * 1e6, 3),
        "enc_throughput": round((n * 8) / enc_el),
        "dec_throughput": round((n * 8) / dec_el),
    })


@app.route("/api/brute_force_estimate")
def api_brute_force():
    bits = int(request.args.get("bits", 80))
    ks   = 2 ** bits
    secs = (ks / 2) / 1e12
    yrs  = secs / (365.25 * 24 * 3600)
    uni  = yrs / 1.38e10
    return jsonify({
        "bits":          bits,
        "years_avg":     f"{yrs:.3e}",
        "universe_ages": f"{uni:.3e}",
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  SecureMed-IoT PRESENT-80 — Demo UI")
    print("  Open http://localhost:5050 in your browser")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
