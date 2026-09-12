#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SET_CONFIGURATION session regression for USB Sniffer 2 (1209:6688).

Background (docs/tasks/set_configuration_ep1_wedge.md):
  A host that re-issues SET_CONFIGURATION(1) through libusb on an
  already-configured device loses EP1 until the device is reset.  Root cause
  is host-side: libusb_set_configuration() uses the usbfs
  USBDEVFS_SETCONFIGURATION ioctl, and the Linux kernel unconditionally calls
  usb_disable_device() when the device is not in ADDRESS state
  (drivers/usb/core/message.c), tearing down the non-EP0 endpoint state.
  The device itself handles a wire-level SET_CONFIGURATION fine, so firmware
  re-arm cannot help.  The supported host rule is F1a: only call
  set_configuration() when the device is not already configured.

Modes:
  f1a    (default) acceptance run with the F1a rule: open -> command A ->
         set_configuration(1) only if the device reports config != 1 ->
         command B -> close, repeated --rounds times.  Expect 0 failures.
  wire   control experiment: same shape, but SET_CONFIGURATION(1) is sent as
         a raw control transfer (bypasses the kernel reconfigure path).
         Shows the device side is unaffected.  Expect 0 failures.
  force  reproduction: always call libusb set_configuration() (no F1a).
         Expected: after EP1 traffic, command B fails with LIBUSB_ERROR_IO
         (errno 5) and stays broken until reset; the script then soft-resets
         the device via vendor request 0xE2 to recover.

Exit status: 0 if the mode's expectation holds, 1 otherwise.

Usage:
  python3 setcfg_regression.py --rounds 50            # f1a acceptance
  python3 setcfg_regression.py --mode wire --rounds 10
  python3 setcfg_regression.py --mode force
"""
import argparse
import struct
import sys
import time

try:
    import usb.core
    import usb.util
except ImportError:
    sys.stderr.write("pyusb is required: pip install pyusb\n")
    sys.exit(2)

VID, PID = 0x1209, 0x6688
EP_OUT, EP_IN = 0x01, 0x81
CMD_ENABLE = 0x02
IAP_RESET_REQ = 0xE2
LIBUSB_ERROR_IO = 5


def crc16(w1, w2, w3):
    """CRC-16/CCITT-FALSE over the 96-bit header W1..W3 (see protocol.md)."""
    crc = 0xFFFF
    for i in range(12):
        w = (w1, w2, w3)[i >> 2]
        crc ^= ((w >> ((i & 3) * 8)) & 0xFF) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_cmd(seq, cid=CMD_ENABLE, param=0):
    w1 = ((seq & 0xFF) << 8) | (cid & 0xFF)
    w3 = 0
    w0 = (crc16(w1, param, w3) << 16) | 0xC7F3
    return b"".join(v.to_bytes(4, "little") for v in (w0, w1, param, w3))


def find_dev():
    return usb.core.find(idVendor=VID, idProduct=PID)


def claim(dev):
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except Exception:
        pass
    usb.util.claim_interface(dev, 0)


def release(dev):
    try:
        usb.util.release_interface(dev, 0)
    except Exception:
        pass


def dev_command(dev, seq, timeout_ms=1000):
    dev.write(EP_OUT, build_cmd(seq), timeout_ms)
    return len(dev.read(EP_IN, 65536, timeout_ms))


def get_configuration(dev):
    """GET_CONFIGURATION over the wire (device view)."""
    data = dev.ctrl_transfer(0x80, 0x08, 0, 0, 1, 1000)
    return int(data[0])


def wait_ready(timeout_s=30, label=""):
    """After a device reset the command interface needs warm-up (~10 s)."""
    deadline = time.time() + timeout_s
    seq = 1
    while time.time() < deadline:
        dev = find_dev()
        if dev is not None:
            try:
                claim(dev)
                n = dev_command(dev, seq)
                release(dev)
                print(f"  {label}device ready ({n} B ACK, {timeout_s - (deadline-time.time()):.0f}s left)")
                return True
            except usb.core.USBError:
                release(dev)
        time.sleep(1.0)
        seq += 1
    return False


def soft_reset():
    dev = find_dev()
    if dev is None:
        return False
    try:
        dev.ctrl_transfer(0x40, IAP_RESET_REQ, 300, 0, b"", 1000)
        return True
    except usb.core.USBError as e:
        print(f"  soft reset request failed: {e}")
        return False


def one_round(mode, rnd):
    """Returns (ok, detail)."""
    dev = find_dev()
    if dev is None:
        return False, "device not found"

    claim(dev)
    try:
        n = dev_command(dev, rnd & 0xFF)
    except usb.core.USBError as e:
        release(dev)
        return False, f"pre command failed errno={e.errno}"
    release(dev)

    try:
        if mode == "force":
            dev.set_configuration()
            cfg_res = "set_configuration(1) [libusb]"
        elif mode == "wire":
            dev.ctrl_transfer(0x00, 0x09, 1, 0, b"", 1000)
            cfg_res = "set_configuration(1) [wire]"
        else:  # f1a
            cfg = get_configuration(dev)
            if cfg != 1:
                dev.set_configuration(1)
                cfg_res = f"set_configuration(1) (was cfg={cfg})"
            else:
                cfg_res = "skipped (already cfg=1)"
    except usb.core.USBError as e:
        cfg_res = f"failed errno={e.errno}"

    try:
        claim(dev)
        n2 = dev_command(dev, 0x80 + (rnd & 0x7F))
        release(dev)
        return True, f"pre=ACK{n}B {cfg_res} post=ACK{n2}B"
    except usb.core.USBError as e:
        release(dev)
        return False, f"pre=ACK{n}B {cfg_res} post=FAIL errno={e.errno}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("f1a", "wire", "force"), default="f1a")
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--no-recover", action="store_true",
                    help="do not soft-reset the device after a force-mode wedge")
    args = ap.parse_args()

    dev = find_dev()
    if dev is None:
        print(f"device {VID:04x}:{PID:04x} not found")
        return 2
    print(f"mode={args.mode} rounds={args.rounds} addr={dev.address}")
    if not wait_ready(30, "warm-up: "):
        print("device command interface not ready (wedged or still booting?)")
        return 2

    failures = 0
    passed = 0
    attempted = 0
    first_fail = None
    for r in range(1, args.rounds + 1):
        attempted = r
        ok, detail = one_round(args.mode, r)
        if not ok:
            failures += 1
            first_fail = first_fail or (r, detail)
            print(f"round {r}: FAIL {detail}")
            if args.mode == "force":
                break  # reproduced; expected
        else:
            passed += 1
            if args.mode != "force" or args.rounds <= 5:
                print(f"round {r}: OK {detail}")

    print(f"== {passed}/{attempted} rounds OK, {failures} failure(s) ==")

    if args.mode == "force":
        if failures == 0:
            print("UNEXPECTED: force mode did not reproduce the wedge")
            return 1
        if first_fail:
            print(f"reproduced: round {first_fail[0]}: {first_fail[1]}")
        if not args.no_recover:
            print("recovering device via vendor 0xE2 soft reset...")
            if soft_reset():
                time.sleep(2)
                if wait_ready(30, "recover: "):
                    print("device recovered")
                else:
                    print("WARNING: device did not recover; power-cycle or Slot A rescue needed")
                    return 1
        return 0

    if failures:
        print(f"FAIL: {failures} failure(s) in mode={args.mode}")
        return 1
    print(f"PASS: {args.rounds}/{args.rounds} rounds zero failure (mode={args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
