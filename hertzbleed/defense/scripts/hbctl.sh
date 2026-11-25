#!/usr/bin/env bash
# hbctl.sh — system knobs for the Hertzbleed defense experiments.
# Everything here needs root (re-execs itself with sudo).
#
#   hbctl.sh status                 show governor/driver/turbo/RAPL/PERF_CTL
#   hbctl.sh rapl-set <W> [<W2>]    set PL1 (long_term) [and PL2] in watts on EVERY package
#                                   (LOWER it to force throttling on high-TDP CPUs)
#   hbctl.sh rapl-raise             PL1/PL2 -> constraint max (so forced P-states hold)
#   hbctl.sh rapl-restore           restore the values saved by the first rapl-* call
#   hbctl.sh turbo on|off           Class 2 "disable turbo" defense
#   hbctl.sh pin-min                Class 2 "fix min freq": scaling_max_freq = min
#   hbctl.sh unpin                  scaling_min/max back to cpuinfo min/max
#   hbctl.sh pstate-passive         intel_pstate -> passive + userspace governor
#                                   (REQUIRED for HB_PSTATE_RAND with msr backend,
#                                   otherwise the kernel rewrites IA32_PERF_CTL)
#   hbctl.sh pstate-active          intel_pstate -> active + powersave (CloudLab default)
#   hbctl.sh perfctl <ratio>        write IA32_PERF_CTL ratio on all CPUs
#   hbctl.sh hwp <ratio>            HWP nodes: force ratio via IA32_HWP_REQUEST min=max
#   hbctl.sh hwp-reset              HWP nodes: restore min/max window (run after hwp backend)
#   hbctl.sh pstate-check           does this node honor OS P-state requests? (run first!)
#   hbctl.sh quiet                  stop noisy services (best effort) before measuring
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"

RAPL=/sys/class/powercap/intel-rapl:0
# every package domain (multi-socket nodes like c220g5 have intel-rapl:0 and :1)
RAPLS=$(ls -d /sys/class/powercap/intel-rapl:[0-9] 2>/dev/null || true)
SAVE=/var/tmp/hb-rapl-orig
CPUS=$(ls -d /sys/devices/system/cpu/cpu[0-9]* | sed 's/.*cpu//' | sort -n)
modprobe msr 2>/dev/null || true

save_rapl() {   # one line per package: <dir> <PL1 uW> <PL2 uW>
  [[ -f $SAVE ]] && return
  for R in $RAPLS; do echo "$R $(cat $R/constraint_0_power_limit_uw) $(cat $R/constraint_1_power_limit_uw)"; done > $SAVE
  echo "saved original RAPL limits to $SAVE: $(tr '\n' ';' < $SAVE)"
}

case "${1:-status}" in
status)
  echo "cpu:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
  echo "driver:    $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver)"
  [[ -f /sys/devices/system/cpu/intel_pstate/status ]] && echo "pstate:    $(cat /sys/devices/system/cpu/intel_pstate/status)  no_turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
  echo "governor:  $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
  echo "min/max:   $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq) / $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq) kHz"
  for R in $RAPLS; do
    for c in 0 1; do
      echo "RAPL $(cat $R/name) c$c:   $(cat $R/constraint_${c}_name) limit=$(cat $R/constraint_${c}_power_limit_uw) max=$(cat $R/constraint_${c}_max_power_uw 2>/dev/null) window=$(cat $R/constraint_${c}_time_window_us)us"
    done
  done
  command -v rdmsr >/dev/null && {
    echo "PLATFORM_INFO(0xCE)=0x$(rdmsr -p0 0xce)  PERF_CTL(0x199) cpu0=0x$(rdmsr -p0 0x199)  PKG_POWER_LIMIT(0x610)=0x$(rdmsr -p0 0x610)"
  }
  ;;
rapl-set)
  save_rapl
  for R in $RAPLS; do   # same per-package limit on every socket
    echo $(( ${2:?watts} * 1000000 )) > $R/constraint_0_power_limit_uw
    [[ -n ${3:-} ]] && echo $(( $3 * 1000000 )) > $R/constraint_1_power_limit_uw
  done
  "$0" status | grep RAPL ;;
rapl-raise)
  save_rapl
  for R in $RAPLS; do for c in 0 1; do cat $R/constraint_${c}_max_power_uw > $R/constraint_${c}_power_limit_uw || true; done; done
  "$0" status | grep RAPL ;;
rapl-restore)
  [[ -f $SAVE ]] || { echo "nothing saved"; exit 0; }
  while read -r R a b; do
    if [[ -z $b ]]; then b=$(sed -n 2p $SAVE); a=$R; R=$RAPL; echo $a > $R/constraint_0_power_limit_uw; echo $b > $R/constraint_1_power_limit_uw; break; fi  # old 2-line format
    echo $a > $R/constraint_0_power_limit_uw; echo $b > $R/constraint_1_power_limit_uw
  done < $SAVE
  rm -f $SAVE; "$0" status | grep RAPL ;;
turbo)
  f=/sys/devices/system/cpu/intel_pstate/no_turbo
  [[ ${2:?on|off} == off ]] && echo 1 > $f || echo 0 > $f
  echo "no_turbo=$(cat $f)" ;;
pin-min)
  for c in $CPUS; do d=/sys/devices/system/cpu/cpu$c/cpufreq
    cat $d/cpuinfo_min_freq > $d/scaling_min_freq; cat $d/cpuinfo_min_freq > $d/scaling_max_freq; done
  "$0" status | grep min/max ;;
unpin)
  for c in $CPUS; do d=/sys/devices/system/cpu/cpu$c/cpufreq
    cat $d/cpuinfo_max_freq > $d/scaling_max_freq; cat $d/cpuinfo_min_freq > $d/scaling_min_freq; done
  "$0" status | grep min/max ;;
pstate-passive)
  echo passive > /sys/devices/system/cpu/intel_pstate/status
  for c in $CPUS; do echo userspace > /sys/devices/system/cpu/cpu$c/cpufreq/scaling_governor; done
  "$0" status | grep -E 'driver|governor' ;;
pstate-active)
  echo active > /sys/devices/system/cpu/intel_pstate/status
  for c in $CPUS; do echo powersave > /sys/devices/system/cpu/cpu$c/cpufreq/scaling_governor; done
  "$0" status | grep -E 'driver|governor' ;;
perfctl)
  r=${2:?ratio}; wrmsr -a 0x199 $(( r << 8 )); echo "PERF_CTL cpu0=0x$(rdmsr -p0 0x199)" ;;
hwp)
  # Force ratio R on every CPU via IA32_HWP_REQUEST (min=max=R, desired=0),
  # keeping EPP/window bits. For HWP nodes (c220g5); disables hwp_dynamic_boost.
  r=${2:?ratio}
  echo 0 > /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost 2>/dev/null || true
  for c in $CPUS; do v=$(( 0x$(rdmsr -p$c 0x774) & ~0xffffff | r << 8 | r )); wrmsr -p$c 0x774 $v; done
  echo "HWP_REQUEST cpu0=0x$(rdmsr -p0 0x774)" ;;
hwp-reset)
  # Undo `hwp R` / HB_PSTATE_BACKEND=hwp leftovers: min=cpuinfo_min, max=cpuinfo_max.
  for c in $CPUS; do d=/sys/devices/system/cpu/cpu$c/cpufreq
    lo=$(( $(cat $d/scaling_min_freq) / 100000 )); hi=$(( $(cat $d/scaling_max_freq) / 100000 ))
    v=$(( 0x$(rdmsr -p$c 0x774) & ~0xffffff | hi << 8 | lo )); wrmsr -p$c 0x774 $v; done
  echo 1 > /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost 2>/dev/null || true
  echo "HWP_REQUEST: $(for c in $CPUS; do rdmsr -p$c 0x774; done | sort | uniq -c | tr '\n' ' ')" ;;
pstate-check)
  # Can the OS actually force a P-state on this node? (FAILS on HPE m510:
  # firmware rewrites IA32_PERF_CTL to max ratio under load, no kernel write
  # involved.) Uses passive mode, writes min ratio on cpu2+sibling, loads cpu2.
  # On HWP nodes (IA32_PM_ENABLE=1, e.g. c220g5) PERF_CTL is ignored, so it
  # tests IA32_HWP_REQUEST min=max instead (=> use HB_PSTATE_BACKEND=hwp).
  lo=$(( (0x$(rdmsr -p0 0xce) >> 40) & 0xff ))
  if (( 0x$(rdmsr -p0 0x770) & 1 )); then
    "$0" hwp $lo >/dev/null
    taskset -c 2 timeout 3 sh -c 'while :; do :; done' &
    sleep 1.5
    got=$(( 0x$(rdmsr -p2 0x774) & 0xff ))
    mhz=$(turbostat -q -c 2 -s CPU,Bzy_MHz -i 1 -n 1 2>/dev/null | tail -1 | awk '{print $2}')
    wait 2>/dev/null || true
    "$0" hwp-reset >/dev/null
    echo "HWP node: requested ratio $lo ($((lo*100)) MHz) via HWP_REQUEST; readback min: $got; busy MHz: $mhz"
    if [[ $got -eq $lo ]] && (( ${mhz%.*} < lo*100 + 150 )); then echo "RESULT: HONORED via HWP (use HB_PSTATE_BACKEND=hwp; msr/PERF_CTL backend is ignored here)"
    else echo "RESULT: OVERRIDDEN (HWP_REQUEST not honored)"; fi
    exit 0
  fi
  prev=$(cat /sys/devices/system/cpu/intel_pstate/status 2>/dev/null || echo none)
  [[ $prev == active ]] && "$0" pstate-passive >/dev/null
  wrmsr -a 0x199 $(( lo << 8 ))
  taskset -c 2 timeout 3 sh -c 'while :; do :; done' &
  sleep 1.5
  got=$(( (0x$(rdmsr -p2 0x199) >> 8) & 0xff ))
  mhz=$(turbostat -q -c 2 -s CPU,Bzy_MHz -i 1 -n 1 2>/dev/null | tail -1 | awk '{print $2}')
  wait 2>/dev/null || true
  [[ $prev == active ]] && "$0" pstate-active >/dev/null
  echo "requested ratio $lo ($((lo*100)) MHz); PERF_CTL readback under load: $got; busy MHz: $mhz"
  if [[ $got -eq $lo ]] && (( ${mhz%.*} < lo*100 + 150 )); then echo "RESULT: HONORED (OS P-state control works; Class 2 forced-P experiments OK)"
  else echo "RESULT: OVERRIDDEN (firmware/HW owns P-states; Class 2 forced-P experiments NOT valid on this node)"; fi ;;
quiet)
  for s in unattended-upgrades apt-daily.timer apt-daily-upgrade.timer snapd; do systemctl stop $s 2>/dev/null || true; done
  echo "stopped background services (best effort)" ;;
*) sed -n '2,22p' "$0"; exit 1 ;;
esac
