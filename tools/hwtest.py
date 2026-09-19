#!/usr/bin/env python3
"""End-to-end hardware acceptance test for the USB Sniffer 2 board.

Flashes a firmware package over the IAP path, verifies the build binding the
device reports back, then runs a sequence of raw captures and judges them with
the project's acceptance criteria (PID validity + SOF CRC5 failures, exactly as
`checkbits.py` reports them).  Designed to run without manual intervention:

    python3 extcap.usb_sniffer2/tools/hwtest.py --pkg <package.iap> \
        [--captures 3] [--seconds 180] [--smoke 30] [--max-fail 0] [--no-ota]

Exit code 0 only if every capture stays within the failure budget and the
device reports the expected build.  Artifacts (raw captures, checker logs and
summary.json) are written to --outdir.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
RAWCAP = os.path.join(HERE, "rawcap.py")
CHECKBITS = os.path.join(HERE, "checkbits.py")
CHECKCAP = os.path.join(HERE, "checkcap.py")
IAP_CLI = os.path.join(REPO, "usb3.ch32h417", "Host", "IAP", "tools", "iap_cli.py")


def run(cmd, timeout, label):
    """Run a command, returning (rc, stdout+stderr)."""
    print(f"[hwtest] $ {' '.join(cmd)}", flush=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, f"{label}: TIMEOUT after {timeout}s\n{e}"
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def iap(args, timeout=180):
    return run(["python3", IAP_CLI] + args, timeout, "iap")


def parse_info(text):
    info = {}
    for key in ("code_hash", "data_hash", "data_length", "build_date"):
        m = re.search(rf"{key}\s*:\s*(\S+)", text)
        if m:
            info[key] = m.group(1)
    return info


def parse_checkbits(text):
    res = {}
    m = re.search(r"frames=(\d+)", text)
    if m:
        res["frames"] = int(m.group(1))
    m = re.search(r"isolated one-frame glitches:\s*(\d+)", text)
    if m:
        res["glitches"] = int(m.group(1))
    m = re.search(r"SOF CRC5 failures:\s*(\d+)", text)
    if m:
        res["crc5_failures"] = int(m.group(1))
    m = re.search(r"of which FPGA crc flag clean:\s*(\d+)", text)
    if m:
        res["crc5_downstream"] = int(m.group(1))
    m = re.search(r"PID valid\s*:\s*(\d+)/(\d+)", text)
    if m:
        res["pid_ok"], res["pid_total"] = int(m.group(1)), int(m.group(2))
    # FPGA status flags (see checkbits.py): sticky flags counted as events,
    # each with the capture position(s) where it became set.
    def flag(name):
        m = re.search(rf"{name}\s+events=(\d+)\s+at=(\S+)", text)
        if not m:
            return None, []
        pos = [float(x) for x in re.findall(r"([0-9.]+)%", m.group(2))]
        return int(m.group(1)), pos
    for name in ("crc_error", "overflow", "data_error"):
        n, pos = flag(name)
        if n is not None:
            res[name + "_events"] = n
            res[name + "_pos"] = pos
    return res


def checkbits_run(path, timeout=300):
    """CRC5 / glitch verdict (the project's acceptance criterion)."""
    return run(["python3", CHECKBITS, path], timeout, "checkbits")


def checkcap_run(path, timeout=300):
    """PID / CRC5 summary (adds the PID validity figure)."""
    return run(["python3", CHECKCAP, path], timeout, "checkcap")


def capture(path, seconds, speed, timeout_pad=90):
    rc, out = run(["python3", RAWCAP, str(seconds), path, speed],
                  seconds + timeout_pad, "rawcap")
    return rc, out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pkg", help="firmware package (.iap) to flash over IAP")
    ap.add_argument("--no-ota", action="store_true", help="skip flashing")
    ap.add_argument("--captures", type=int, default=3, help="number of long captures (default 3)")
    ap.add_argument("--seconds", type=int, default=180, help="long capture length (default 180)")
    ap.add_argument("--smoke", type=int, default=30, help="smoke capture length, 0=skip (default 30)")
    ap.add_argument("--speed", default="auto", help="capture speed mode (default auto)")
    ap.add_argument("--max-fail", type=int, default=0,
                    help="allowed SOF CRC5 failures per capture (default 0)")
    ap.add_argument("--max-drop-events", type=int, default=0,
                    help="allowed in-capture FPGA overflow/data-error events "
                         "(boundary transients at <=1%%/>=99%% are only reported); "
                         "default 0")
    ap.add_argument("--min-frames", type=int, default=100000,
                    help="minimum 3-byte frames per long capture (throughput sanity, default 100000)")
    ap.add_argument("--outdir", default=None, help="artifact directory")
    args = ap.parse_args()

    if not args.no_ota and not args.pkg:
        ap.error("--pkg is required unless --no-ota is given")
    if not os.path.exists(RAWCAP) or not os.path.exists(CHECKBITS):
        ap.error(f"tools not found next to {HERE}")

    outdir = args.outdir or os.path.join(
        "/tmp/kilo", "hwtest-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    summary = {"started": datetime.now().isoformat(), "outdir": outdir,
               "speed": args.speed, "seconds": args.seconds, "max_fail": args.max_fail,
               "steps": []}
    ok = True

    def drop_verdict(r):
        """Return (pass, detail).  Boundary transients (<=1% or >=99% of the
        capture: capture start / stop while the pipe is still filling or
        draining) are reported but not counted as failures."""
        interior, boundary = [], []
        for k in ("overflow", "data_error"):
            for pos in r.get(k + "_pos", []):
                (boundary if (pos <= 1.0 or pos >= 99.0) else interior).append(f"{k}@{pos:.1f}%")
        detail = (f"drop-events: interior={len(interior)}"
                  + (f" {interior}" if interior else "")
                  + (f" boundary={len(boundary)} {boundary}" if boundary else ""))
        return len(interior) <= args.max_drop_events, detail

    def step(name, passed, detail):
        nonlocal ok
        summary["steps"].append({"step": name, "pass": passed, "detail": detail})
        print(f"[hwtest] {'PASS' if passed else 'FAIL'}  {name}: {detail}", flush=True)
        if not passed:
            ok = False

    # ---- 1. flash + build binding -----------------------------------------
    if not args.no_ota:
        rc, out = iap(["update", args.pkg, "--auto-reset"])
        step("ota", rc == 0 and "CRC check passed" in out,
             f"rc={rc} " + ("written+verified" if rc == 0 else out.strip()[-200:]))
        summary["pkg"] = os.path.abspath(args.pkg)
        time.sleep(3)

    rc, out = iap(["info"])
    info = parse_info(out)
    summary["device"] = info
    ota_ok = rc == 0 and bool(info.get("code_hash"))
    step("device-info", ota_ok, json.dumps(info))

    # ---- 2. smoke capture --------------------------------------------------
    caps = []
    if args.smoke > 0:
        p = os.path.join(outdir, f"smoke-{args.smoke}s.bin")
        rc, out = capture(p, args.smoke, args.speed)
        rc2, chk = checkbits_run(p)
        rc3, sumr = checkcap_run(p)
        r = parse_checkbits(chk + "\n" + sumr)
        caps.append({"name": "smoke", "seconds": args.smoke, "path": p, **r})
        dv, ddet = drop_verdict(r)
        step("smoke", rc == 0 and rc2 == 0 and rc3 == 0 and r.get("frames", 0) > 0
             and r.get("pid_ok") == r.get("pid_total") and r.get("pid_total", 0) > 0
             and r.get("crc5_failures", 1) <= args.max_fail and dv,
             f"frames={r.get('frames')} crc5={r.get('crc5_failures')} "
             f"pid={r.get('pid_ok')}/{r.get('pid_total')} {ddet}")

    # ---- 3. long captures --------------------------------------------------
    for i in range(1, args.captures + 1):
        p = os.path.join(outdir, f"cap{i}-{args.seconds}s.bin")
        rc, out = capture(p, args.seconds, args.speed)
        rc2, chk = checkbits_run(p, timeout=args.seconds + 120)
        rc3, sumr = checkcap_run(p, timeout=args.seconds + 120)
        open(os.path.join(outdir, f"cap{i}-checkbits.txt"), "w").write(chk)
        open(os.path.join(outdir, f"cap{i}-checkcap.txt"), "w").write(sumr)
        r = parse_checkbits(chk + "\n" + sumr)
        caps.append({"name": f"cap{i}", "seconds": args.seconds, "path": p, **r})
        dv, ddet = drop_verdict(r)
        passed = (rc == 0 and rc2 == 0 and rc3 == 0
                  and r.get("frames", 0) >= args.min_frames
                  and r.get("pid_ok") == r.get("pid_total") and r.get("pid_total", 0) > 0
                  and r.get("crc5_failures", 1) <= args.max_fail and dv)
        step(f"capture-{i}", passed,
             f"frames={r.get('frames')} crc5={r.get('crc5_failures')} "
             f"(downstream={r.get('crc5_downstream')}) glitches={r.get('glitches')} "
             f"pid={r.get('pid_ok')}/{r.get('pid_total')} {ddet}")

    summary["captures"] = caps
    summary["pass"] = ok
    summary["finished"] = datetime.now().isoformat()
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    total = sum(c.get("crc5_failures", 0) for c in caps)
    frames = sum(c.get("frames", 0) for c in caps)
    drops = sum(c.get("overflow_events", 0) + c.get("data_error_events", 0) for c in caps)
    print("\n[hwtest] ====================== SUMMARY ======================")
    print(f"[hwtest] captures   : {len(caps)} ({', '.join(str(c['seconds'])+'s' for c in caps)})")
    print(f"[hwtest] frames     : {frames}")
    print(f"[hwtest] CRC5 fails : {total} (budget {args.max_fail}/capture)")
    print(f"[hwtest] drop events: {drops} (in-capture budget {args.max_drop_events}/capture; "
          f"positions per capture in the steps above)")
    print(f"[hwtest] artifacts  : {outdir}")
    print(f"[hwtest] RESULT     : {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
