"""
benchmark.py – PRESENT-80 Performance Benchmark
================================================
Benchmarks the pure-Python PRESENT-80 implementation and compares it
to AES-128 (via the cryptography library if available, else pycryptodome).

Output
------
  - Formatted table printed to stdout
  - benchmark_results.json  – machine-readable results
  - benchmark_plot.png      – histogram of per-encryption latency
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from typing import Any

from present import PRESENT

# --------------------------------------------------------------------------- #
#  Benchmark helpers
# --------------------------------------------------------------------------- #

def _random_cipher() -> tuple[PRESENT, int]:
    """Return a fresh cipher and a random 64-bit plaintext."""
    key    = os.urandom(10)
    pt     = random.getrandbits(64)
    cipher = PRESENT(key)
    return cipher, pt


def benchmark_encryption(n: int = 10_000) -> dict[str, Any]:
    """
    Benchmark PRESENT-80 encryption.

    Parameters
    ----------
    n : Number of encryption operations.

    Returns
    -------
    dict with keys:
        n             – operations performed
        total_sec     – wall-clock seconds for n ops
        avg_us        – average microseconds per operation
        throughput_bps – bytes per second (8 bytes per 64-bit block)
    """
    cipher, pt = _random_cipher()
    # Warm-up
    for _ in range(min(100, n)):
        cipher.encrypt(pt)

    start = time.perf_counter()
    ct    = pt
    for _ in range(n):
        ct = cipher.encrypt(ct)      # chain to prevent dead-code elimination
    total_sec = time.perf_counter() - start

    avg_us         = (total_sec / n) * 1e6
    throughput_bps = (n * 8) / total_sec  # 8 bytes per block

    return {
        "n": n,
        "total_sec": round(total_sec, 6),
        "avg_us": round(avg_us, 4),
        "throughput_bps": round(throughput_bps, 2),
    }


def benchmark_decryption(n: int = 10_000) -> dict[str, Any]:
    """
    Benchmark PRESENT-80 decryption.

    Returns
    -------
    Same structure as benchmark_encryption.
    """
    cipher, pt = _random_cipher()
    ct = cipher.encrypt(pt)

    # Warm-up
    for _ in range(min(100, n)):
        cipher.decrypt(ct)

    start = time.perf_counter()
    block = ct
    for _ in range(n):
        block = cipher.decrypt(block)
    total_sec = time.perf_counter() - start

    avg_us         = (total_sec / n) * 1e6
    throughput_bps = (n * 8) / total_sec

    return {
        "n": n,
        "total_sec": round(total_sec, 6),
        "avg_us": round(avg_us, 4),
        "throughput_bps": round(throughput_bps, 2),
    }


def memory_usage() -> dict[str, float]:
    """
    Return current process memory usage via psutil.

    Returns
    -------
    dict with keys: rss_mb (Resident Set Size), vms_mb (Virtual Memory Size).
    """
    try:
        import psutil  # type: ignore[import]
        proc = psutil.Process(os.getpid())
        mem  = proc.memory_info()
        return {
            "rss_mb": round(mem.rss / (1024 ** 2), 3),
            "vms_mb": round(mem.vms / (1024 ** 2), 3),
        }
    except ImportError:
        print("[WARN] psutil not installed. Run: pip install psutil", file=sys.stderr)
        return {"rss_mb": -1.0, "vms_mb": -1.0}


def compare_with_aes(n: int = 10_000) -> dict[str, Any]:
    """
    Compare PRESENT-80 vs AES-128 single-block encryption timing.

    Uses the ``cryptography`` library (preferred) or ``pycryptodome``.
    If neither is available, AES results are marked as unavailable.

    Returns
    -------
    dict with keys:
        present_avg_us, present_throughput_bps,
        aes_avg_us, aes_throughput_bps,
        speedup_factor  (aes / present – >1 means PRESENT is faster)
    """
    # --- PRESENT ---
    cipher_p, pt = _random_cipher()
    start = time.perf_counter()
    ct_p  = pt
    for _ in range(n):
        ct_p = cipher_p.encrypt(ct_p)
    present_total = time.perf_counter() - start
    present_avg_us         = (present_total / n) * 1e6
    present_throughput_bps = (n * 8) / present_total

    # --- AES-128 ---
    aes_avg_us         = -1.0
    aes_throughput_bps = -1.0
    aes_library        = "unavailable"

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore[import]
        from cryptography.hazmat.backends import default_backend               # type: ignore[import]
        aes_key = os.urandom(16)
        aes_iv  = os.urandom(16)
        pt_bytes = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(aes_iv),
            backend=default_backend(),
        ).encryptor()
        # Warm-up
        for _ in range(min(100, n)):
            encryptor.update(pt_bytes)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(aes_iv),
            backend=default_backend(),
        ).encryptor()
        start = time.perf_counter()
        for _ in range(n):
            encryptor.update(pt_bytes)
        aes_total = time.perf_counter() - start
        aes_avg_us         = (aes_total / n) * 1e6
        aes_throughput_bps = (n * 16) / aes_total  # AES block = 16 bytes
        aes_library        = "cryptography"
    except ImportError:
        try:
            from Crypto.Cipher import AES as _AES  # type: ignore[import]
            aes_key   = os.urandom(16)
            pt_bytes  = os.urandom(16)
            aes_ciph  = _AES.new(aes_key, _AES.MODE_ECB)
            # Warm-up
            for _ in range(min(100, n)):
                aes_ciph.encrypt(pt_bytes)
            aes_ciph  = _AES.new(aes_key, _AES.MODE_ECB)
            start     = time.perf_counter()
            for _ in range(n):
                aes_ciph.encrypt(pt_bytes)
            aes_total = time.perf_counter() - start
            aes_avg_us         = (aes_total / n) * 1e6
            aes_throughput_bps = (n * 16) / aes_total
            aes_library        = "pycryptodome"
        except ImportError:
            print("[WARN] Neither 'cryptography' nor 'pycryptodome' installed; "
                  "AES comparison unavailable.", file=sys.stderr)

    speedup = (aes_avg_us / present_avg_us) if aes_avg_us > 0 else None

    return {
        "n": n,
        "present_avg_us":         round(present_avg_us, 4),
        "present_throughput_bps": round(present_throughput_bps, 2),
        "aes_avg_us":             round(aes_avg_us, 4),
        "aes_throughput_bps":     round(aes_throughput_bps, 2) if aes_avg_us > 0 else -1,
        "aes_library":            aes_library,
        "speedup_factor":         round(speedup, 4) if speedup is not None else None,
    }


# --------------------------------------------------------------------------- #
#  Per-operation timing sample (for histogram)
# --------------------------------------------------------------------------- #

def _sample_encryption_times(n: int = 1000) -> list[float]:
    """Return a list of n individual encryption latencies in microseconds."""
    cipher, pt = _random_cipher()
    times: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        pt = cipher.encrypt(pt)
        times.append((time.perf_counter() - t0) * 1e6)
    return times


# --------------------------------------------------------------------------- #
#  Plotting
# --------------------------------------------------------------------------- #

def plot_histogram(times_us: list[float], out_path: str = "benchmark_plot.png") -> None:
    """Save a histogram of per-encryption latencies."""
    try:
        import matplotlib  # type: ignore[import]
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore[import]
    except ImportError:
        print("[WARN] matplotlib not installed. Skipping plot. "
              "Run: pip install matplotlib", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(times_us, bins=40, color="#2196F3", edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Encryption latency (µs)", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("PRESENT-80 Per-Encryption Latency Distribution (Python)", fontsize=13)

    mean_us = sum(times_us) / len(times_us)
    ax.axvline(mean_us, color="#F44336", linestyle="--", linewidth=1.5,
               label=f"Mean: {mean_us:.2f} µs")
    ax.legend()

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[INFO] Histogram saved to {out_path}")


# --------------------------------------------------------------------------- #
#  Pretty-print table
# --------------------------------------------------------------------------- #

def _print_table(title: str, rows: list[tuple[str, str]]) -> None:
    col_w = 32
    val_w = 20
    sep   = "+" + "-" * (col_w + 2) + "+" + "-" * (val_w + 2) + "+"
    print()
    print(f"  {title}")
    print(sep)
    for label, value in rows:
        print(f"| {label:<{col_w}} | {value:>{val_w}} |")
    print(sep)


def print_results(enc: dict, dec: dict, mem: dict, aes: dict) -> None:
    _print_table("PRESENT-80 Encryption Benchmark", [
        ("Operations",           f"{enc['n']:,}"),
        ("Total time (s)",       f"{enc['total_sec']:.4f}"),
        ("Avg latency (µs)",     f"{enc['avg_us']:.4f}"),
        ("Throughput (B/s)",     f"{enc['throughput_bps']:,.1f}"),
    ])
    _print_table("PRESENT-80 Decryption Benchmark", [
        ("Operations",           f"{dec['n']:,}"),
        ("Total time (s)",       f"{dec['total_sec']:.4f}"),
        ("Avg latency (µs)",     f"{dec['avg_us']:.4f}"),
        ("Throughput (B/s)",     f"{dec['throughput_bps']:,.1f}"),
    ])
    _print_table("Process Memory Usage", [
        ("RSS (MB)",             f"{mem['rss_mb']:.3f}"),
        ("VMS (MB)",             f"{mem['vms_mb']:.3f}"),
    ])
    aes_rows: list[tuple[str, str]] = [
        ("Library used",         aes["aes_library"]),
        ("PRESENT avg (µs)",     f"{aes['present_avg_us']:.4f}"),
        ("AES avg (µs)",         f"{aes['aes_avg_us']:.4f}" if aes["aes_avg_us"] > 0 else "N/A"),
        ("AES throughput (B/s)", f"{aes['aes_throughput_bps']:,.1f}" if aes["aes_throughput_bps"] > 0 else "N/A"),
        ("Speedup (AES/PRESENT)",
         f"{aes['speedup_factor']:.4f}x" if aes["speedup_factor"] is not None else "N/A"),
    ]
    _print_table("PRESENT-80 vs AES-128 Comparison", aes_rows)


# --------------------------------------------------------------------------- #
#  Main entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    n_ops   = 10_000
    n_hist  = 1_000

    print(f"Running PRESENT-80 benchmarks ({n_ops:,} ops each) …")
    enc_result = benchmark_encryption(n_ops)
    dec_result = benchmark_decryption(n_ops)
    mem_result = memory_usage()
    aes_result = compare_with_aes(n_ops)

    print_results(enc_result, dec_result, mem_result, aes_result)

    # Collect per-operation samples for the histogram
    print(f"\nSampling {n_hist} individual encryption times for histogram …")
    sample_times = _sample_encryption_times(n_hist)
    plot_histogram(sample_times, "benchmark_plot.png")

    # Save JSON results
    results = {
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "encryption": enc_result,
        "decryption": dec_result,
        "memory":     mem_result,
        "aes_comparison": aes_result,
    }
    out_path = "benchmark_results.json"
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\n[INFO] Full results saved to {out_path}")


if __name__ == "__main__":
    main()
