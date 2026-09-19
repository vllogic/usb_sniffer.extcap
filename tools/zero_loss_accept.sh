#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
#
# zero_loss_accept.sh -- "完美抓包" acceptance: 4-byte-granularity integrity of
# USB Sniffer 2 at the USB 2.0 HS limit, for idle / single-stream / 4-way.
#
# Each case: generate U-disk traffic, capture with tools/usbcap_fast (async
# writer), then verify EVERY 32-bit word with tools/patcheck.py against the
# self-describing pattern file (stress_pat.bin).
#
# Harness hard-won requirements (each fixes a measured test artifact):
#   * PRE-FLIGHT SuperSpeed: if the sniffer enumerates on the USB2 half of the
#     hub (Bus001 480M, same bus as the U-disk) the uplink shares 480 Mbps and
#     EVERYTHING overflows.  Abort/reset unless speed==5000.
#   * TMPFS HYGIENE: a 20-30 s run at ~46 MB/s is ~1.0-1.4 GB; leftover files
#     (or a raw that is not removed) make write() fail/stall -> fake overflow.
#     Guard free space and remove the raw every case.
#   * PROCESS-GROUP KILL of readers (+ no-residual-dd assertion): a plain
#     `kill` of the loop subshell does not reliably reap an in-flight dd.
#   * RESIDUAL FLUSH before idle: the device can still hold capture data from
#     the previous session and flush it at the next ENABLE; a throwaway
#     capture drains it so "idle" is really idle.
#   * readers are `nice -n 19` when >1: the traffic source and the sniffer host
#     are the same machine here; deprioritising the synthetic readers emulates
#     the real deployment (source on the *target* machine).  Without it, 4
#     CPU-bound readers starve the tool's libusb event loop and overflow.
#   * once-through cases read each byte exactly ONCE (capture armed first), so
#     a dropped packet cannot be masked by a later pass.
#
# Usage:
#   UDISK_PAT=/mnt/udisk/stress_pat.bin ROUNDS=3 SECS=20 ./zero_loss_accept.sh
# Env: ROUNDS SECS ONCE_SECS OUT RAW URBS URBSZ UDISK_PAT MIB NO_RESET
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PAT=${UDISK_PAT:-/mnt/udisk/stress_pat.bin}
SECS=${SECS:-20}
ONCE_SECS=${ONCE_SECS:-12}
ROUNDS=${ROUNDS:-3}
OUT=${OUT:-/home/llp/stress-out/acc}
RAW=${RAW:-/dev/shm/zero_loss_acc.bin}
URBS=${URBS:-8}
URBSZ=${URBSZ:-262144}
MIB=${MIB:-128}

[ -f "$PAT" ] || { echo "pattern file missing: $PAT (see usb_stress.py prep)"; exit 2; }

sniffer_speed() {
  local d
  for d in /sys/bus/usb/devices/*; do
    [ -f "$d/idVendor" ] || continue
    [ "$(cat "$d/idVendor" 2>/dev/null)" = "1209" ] || continue
    [ "$(cat "$d/idProduct" 2>/dev/null)" = "6688" ] || continue
    cat "$d/speed" 2>/dev/null; return 0
  done
  echo 0
}

preflight_ss() {
  local spd; spd=$(sniffer_speed)
  if [ "$spd" != "5000" ]; then
    echo "!! sniffer NOT SuperSpeed (speed='$spd'); issuing IAP reset ..."
    [ "${NO_RESET:-0}" = "1" ] && { echo "FATAL: NO_RESET=1 and not SS"; exit 3; }
    python3 "$REPO/usb3.ch32h417/Host/IAP/tools/iap_cli.py" reset >/dev/null 2>&1 || true
    sleep 6; spd=$(sniffer_speed)
  fi
  [ "$spd" = "5000" ] || { echo "FATAL: sniffer still not SuperSpeed (speed='$spd'); fix USB3 link then rerun"; exit 3; }
  echo "== sniffer: SuperSpeed 5000M =="
}

# free-space guard for /dev/shm raws (SECS*60MB/s worst case + 300MB slack)
guard_space() {
  case "$RAW" in
    /dev/shm/*)
      local avail need
      avail=$(df -Pk /dev/shm | awk 'NR==2{print $4}')
      need=$(( SECS * 60000 + 300000 ))
      if [ "$avail" -lt "$need" ]; then
        echo "FATAL: /dev/shm free ${avail}KB < ${need}KB (leftover raws?). Clean it or lower SECS."; exit 3
      fi
      ;;
  esac
}

assert_no_residual_dd() {
  if pgrep -f "dd if=$PAT" >/dev/null 2>&1; then
    echo "!! residual reader before $1 -> killing"; pkill -f "dd if=$PAT" 2>/dev/null; sleep 0.5
  fi
}

BUILD=$(mktemp -d)
gcc -O2 -pthread -o "$BUILD/usbcap_fast" "$HERE/usbcap_fast.c" \
    $(pkg-config --cflags --libs libusb-1.0) || { echo "usbcap_fast build failed"; exit 2; }
CAP="$BUILD/usbcap_fast"
mkdir -p "$OUT"
FAIL=0
RL_PIDS=""

{ echo "date=$(date -Is)"; echo "git=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)";
  echo "ROUNDS=$ROUNDS SECS=$SECS ONCE_SECS=$ONCE_SECS URBS=$URBS URBSZ=$URBSZ MIB=$MIB";
  echo "RAW=$RAW"; echo "cmdline=$0 $*"; } > "$OUT/env.txt"

start_readers() {   # start_readers <readers> <bs> <disjoint:0|1> <loop:0|1> <end_epoch>
  local readers=$1 bs=$2 disjoint=$3 loop=$4 end=$5
  RL_PIDS=""
  local bn=${bs%M}; [ "$bn" -lt 1 ] && bn=1
  local per=$(( MIB / readers )); local off=0 i cnt sk ct cmd
  for i in $(seq 1 "$readers"); do
    cnt=$per; [ "$i" -eq "$readers" ] && cnt=$(( MIB - off ))
    sk=$(( off / bn )); ct=$(( cnt / bn ))
    if [ "$disjoint" = 1 ]; then
      cmd="nice -n 19 dd if=$PAT of=/dev/null bs=$bs iflag=direct skip=$sk count=$ct"
    else
      cmd="nice -n 19 dd if=$PAT of=/dev/null bs=$bs iflag=direct"
    fi
    if [ "$loop" = 1 ]; then
      setsid bash -c "while [ \$(date +%s) -lt $end ]; do $cmd 2>/dev/null; done" &
    else
      setsid bash -c "$cmd 2>/dev/null" &
    fi
    RL_PIDS="$RL_PIDS $!"
    off=$(( off + per ))
  done
}
stop_readers() {
  local p tries=0
  for p in $RL_PIDS; do kill -- -"$p" 2>/dev/null; done   # whole process group
  for p in $RL_PIDS; do kill "$p" 2>/dev/null; done
  for p in $RL_PIDS; do wait "$p" 2>/dev/null; done
  while pgrep -f "dd if=$PAT" >/dev/null 2>&1 && [ "$tries" -lt 20 ]; do sleep 0.1; tries=$((tries+1)); done
  pgrep -f "dd if=$PAT" >/dev/null 2>&1 && pkill -f "dd if=$PAT" 2>/dev/null
  RL_PIDS=""
}

flush_residual() {   # drain any capture data left in the device from the last session
  "$CAP" 0.8 /dev/null hs --no-write --urbs "$URBS" --urb-size "$URBSZ" >/dev/null 2>&1
}

run_case() {   # run_case <name> <secs> <speed> <readers> <disjoint> <loop> <flush:0|1> [patcheck args...]
  local name=$1 secs=$2 speed=$3 readers=$4 disjoint=$5 loop=$6 flush=$7; shift 7
  local end=$(( $(date +%s) + secs + 8 ))
  # Always drain residual device data first: otherwise the previous session's
  # pool content can be flushed into THIS capture as an isolated far-away
  # packet, inflating patcheck's span and fabricating a huge MISSING gap.
  flush_residual
  assert_no_residual_dd "$name"
  rm -f "$RAW"
  if [ "$loop" = 0 ] && [ "$readers" -gt 0 ]; then
    # once-through: ENABLE capture FIRST, then read (no byte read before arming)
    "$CAP" "$secs" "$RAW" "$speed" --urbs "$URBS" --urb-size "$URBSZ" > "$OUT/$name.cap.txt" 2>&1 &
    local cappid=$!
    sleep 0.6
    start_readers "$readers" 4M "$disjoint" 0 "$end"
    wait "$cappid"
    stop_readers
  else
    [ "$readers" -gt 0 ] && start_readers "$readers" 4M "$disjoint" "$loop" "$end"
    [ "$readers" -gt 0 ] && sleep 0.4
    "$CAP" "$secs" "$RAW" "$speed" --urbs "$URBS" --urb-size "$URBSZ" > "$OUT/$name.cap.txt" 2>&1
    stop_readers
  fi
  grep -q 'WARNING' "$OUT/$name.cap.txt" && echo "!! $name: capture tool reported a WRITE ERROR (raw truncated)"
  ( cd "$HERE/.." && python3 "$HERE/patcheck.py" "$RAW" "$@" ) > "$OUT/$name.txt" 2>&1
  echo "### $name"
  grep -E 'MISSING words|stream gaps|FPGA flag events|WRONG words|VERDICT' "$OUT/$name.txt"
  grep -q 'VERDICT.*PERFECT' "$OUT/$name.txt" || FAIL=1
  rm -f "$RAW"
}

preflight_ss
guard_space

for r in $(seq 1 "$ROUNDS"); do
  run_case "idle_r$r"             "$SECS"      hs   0 0 0 1
  run_case "single_sustained_r$r" "$SECS"      hs   1 0 1 0 --slices 1
  run_case "quad_slices_r$r"      "$SECS"      hs   4 1 1 0 --slices 4
  run_case "quad_overlap_r$r"     "$SECS"      hs   4 0 1 0
done
run_case "single_once_r1"       "$ONCE_SECS" hs   1 1 0 0 --slices 1
run_case "quad_once_r1"         "$ONCE_SECS" hs   4 1 0 0 --slices 4
run_case "quad_slices_auto_r1"  "$SECS"      auto 4 1 1 0 --slices 4

rm -rf "$BUILD"
echo "=== zero-loss acceptance: $([ $FAIL -eq 0 ] && echo ALL PERFECT || echo ANOMALY) ; logs+env in $OUT ==="
exit $FAIL
