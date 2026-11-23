#!/usr/bin/env python3
"""averaging_curve.py — signal distinguishability vs. number of averaged samples K.

THE reused measurement of the project (baseline anchor, noise-injection eval,
rate-limit / key-rotation analysis, formal section).

Inputs: two sample files, class 0 (m_i == m_{i-1}, flip=0) and class 1
(flip=1). Each file is either sike_local stdout (lines "ALL_DURATION 78.1ms")
or one number per line. Optionally a column of a freqlog CSV (--csv-col).

For each K it reports:
  acc_boot  bootstrap accuracy of the midpoint-threshold classifier applied
            to means of K samples (only when K <= N/2, else NaN)
  acc_gauss Gaussian prediction Phi(|d| sqrt(K) / 2), d = Cohen's d
  t_welch   expected Welch t of two K-sample groups = d * sqrt(K/2)
and K99 = smallest K with predicted accuracy >= 0.99, plus a time-to-key
estimate (K99 * bits) for the rate-limit / key-rotation analyses.

    ./averaging_curve.py f0.txt f1.txt [-K 1,10,100,1000,10000] [--csv out.csv] [--plot out.png]
"""
import argparse
import math
import re
import sys

import numpy as np

UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
GO_DUR = re.compile(r"([0-9.]+)(ns|us|µs|μs|ms|s|m|h)")


def go_duration(s):
    tot, pos = 0.0, 0
    for m in GO_DUR.finditer(s):
        tot += float(m.group(1)) * UNITS[m.group(2)]
        pos = m.end()
    if pos != len(s):
        raise ValueError(s)
    return tot


def load(path, csv_col=None, skip=0):
    xs = []
    with open(path) as f:
        if csv_col is not None:
            hdr = f.readline().strip().split(",")
            j = hdr.index(csv_col)
            xs = [float(l.split(",")[j]) for l in f if l.strip()]
        else:
            for line in f:
                line = line.strip()
                if line.startswith("ALL_DURATION"):
                    xs.append(go_duration(line.split()[1]))
                elif line and re.fullmatch(r"[-+0-9.eE]+", line):
                    xs.append(float(line))
    return np.asarray(xs[skip:], dtype=float)


def phi(x):
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("class0")
    ap.add_argument("class1")
    ap.add_argument("-K", default="1,10,100,1000,10000")
    ap.add_argument("--csv-col", help="column name if inputs are CSV (e.g. f_cpu0_khz)")
    ap.add_argument("--skip", type=int, default=1, help="drop first N samples (warm-up)")
    ap.add_argument("--trim", type=float, default=0.0, help="drop this fraction of outliers at each tail")
    ap.add_argument("--boot", type=int, default=2000)
    ap.add_argument("--bits", type=int, default=378, help="key bits for time-to-key")
    ap.add_argument("--csv")
    ap.add_argument("--plot")
    ap.add_argument("--label", default="")
    a = ap.parse_args()

    x0, x1 = load(a.class0, a.csv_col, a.skip), load(a.class1, a.csv_col, a.skip)
    if a.trim > 0:
        def tr(x):
            lo, hi = np.quantile(x, [a.trim, 1 - a.trim])
            return x[(x >= lo) & (x <= hi)]
        x0, x1 = tr(x0), tr(x1)
    if len(x0) < 2 or len(x1) < 2:
        sys.exit("need >= 2 samples per class")
    m0, m1 = x0.mean(), x1.mean()
    sd = math.sqrt((x0.var(ddof=1) + x1.var(ddof=1)) / 2)
    d = abs(m1 - m0) / sd if sd > 0 else float("inf")
    print(f"# {a.label} N0={len(x0)} N1={len(x1)} mean0={m0:.6g} mean1={m1:.6g} "
          f"delta={m1 - m0:+.4g} ({100 * (m1 - m0) / m0:+.3f}%) pooled_sd={sd:.4g} cohen_d={d:.4f}")

    rng = np.random.default_rng(0)
    thr, sign = (m0 + m1) / 2, (1 if m1 > m0 else -1)
    rows = []
    for K in [int(k) for k in a.K.split(",")]:
        acc_g = phi(d * math.sqrt(K) / 2)
        t_w = d * math.sqrt(K / 2)
        acc_b = float("nan")
        if K <= min(len(x0), len(x1)) // 2:
            b0 = rng.choice(x0, (a.boot, K)).mean(1)
            b1 = rng.choice(x1, (a.boot, K)).mean(1)
            acc_b = 0.5 * (np.mean(sign * (b0 - thr) < 0) + np.mean(sign * (b1 - thr) > 0))
        rows.append((K, acc_b, acc_g, t_w))
        print(f"K={K:>6}  acc_boot={acc_b:.4f}  acc_gauss={acc_g:.4f}  t_welch={t_w:.2f}")

    # smallest K with predicted accuracy >= 0.99: |d| sqrt(K)/2 >= 2.326
    k99 = math.ceil((2 * 2.3263 / d) ** 2) if d > 0 else float("inf")
    print(f"K99 = {k99}  -> time-to-key ~ {k99} x {a.bits} bits = {k99 * a.bits if k99 != float('inf') else 'inf'} "
          f"measurements (x samples/measurement)")

    if a.csv:
        with open(a.csv, "w") as f:
            f.write("label,K,acc_boot,acc_gauss,t_welch,cohen_d,k99\n")
            for K, ab, ag, tw in rows:
                f.write(f"{a.label},{K},{ab},{ag},{tw},{d},{k99}\n")
    if a.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        Ks = [r[0] for r in rows]
        plt.figure(figsize=(4.5, 3.2))
        plt.semilogx(Ks, [r[2] for r in rows], "o-", label="Gaussian prediction")
        plt.semilogx(Ks, [r[1] for r in rows], "s--", label="bootstrap")
        plt.axhline(0.5, color="gray", lw=0.8)
        plt.ylim(0.45, 1.01)
        plt.xlabel("samples averaged K")
        plt.ylabel("classification accuracy")
        plt.title(a.label or "averaging curve")
        plt.legend()
        plt.tight_layout()
        plt.savefig(a.plot, dpi=200)


if __name__ == "__main__":
    main()
