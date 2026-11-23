#!/usr/bin/env python3
"""freqlog.py — sample per-CPU frequency (+ package energy) every PERIOD ms.

    sudo ./freqlog.py -o out.csv -p 5 -d 60 [-c 0,2,4]

CSV columns: t_s, energy_uj (package, -1 if unreadable), f_cpu<N>_khz...
Frequency comes from scaling_cur_freq (APERF/MPERF-derived on intel_pstate).
For the paper's steady-state histograms use the last 20 s (see --tail in
averaging_curve.py / your plotting code).
"""
import argparse
import os
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("-o", "--out", required=True)
p.add_argument("-p", "--period-ms", type=float, default=5.0)
p.add_argument("-d", "--duration-s", type=float, default=60.0)
p.add_argument("-c", "--cpus", default="", help="comma list; default all")
a = p.parse_args()

ncpu = os.cpu_count()
cpus = [int(x) for x in a.cpus.split(",") if x] or list(range(ncpu))
ffiles = [open(f"/sys/devices/system/cpu/cpu{c}/cpufreq/scaling_cur_freq") for c in cpus]
try:
    efile = open("/sys/class/powercap/intel-rapl:0/energy_uj")
except OSError:
    efile = None
    print("warning: energy_uj unreadable (run as root)", file=sys.stderr)


def rd(f):
    f.seek(0)
    return f.read().strip()


period = a.period_ms / 1000.0
with open(a.out, "w") as out:
    out.write("t_s,energy_uj," + ",".join(f"f_cpu{c}_khz" for c in cpus) + "\n")
    t0 = time.perf_counter()
    nxt = t0
    while True:
        now = time.perf_counter()
        if now - t0 > a.duration_s:
            break
        e = rd(efile) if efile else "-1"
        out.write(f"{now - t0:.6f},{e}," + ",".join(rd(f) for f in ffiles) + "\n")
        nxt += period
        time.sleep(max(0.0, nxt - time.perf_counter()))
