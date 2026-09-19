#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""rawcap.py -- capture the sniffer uplink stream verbatim.

Unlike uhsif_capture.py this does NOT parse the capture-frame layer: it writes
the raw payload byte stream (UHSIF data blocks) to a file, so it still works
when the payload is corrupt (the frame parser in uhsif_capture.py aborts with an
IndexError on a corrupt stream).

Init sequence per docs/protocol.md: Enable 0 -> Reset 1 -> Speed -> Reset 0 ->
Enable 1.

Usage: python3 rawcap.py <seconds> <out.bin> [ls|fs|hs|auto]
"""
import os
import sys
import time

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import usb.core  # noqa: E402
import usb.util  # noqa: E402

from uhsif_loopback_test import Stream, build_cmd, CMD_RESET, CMD_ENABLE, CMD_SPEED  # noqa: E402

VID, PID = 0x1209, 0x6688
EP_OUT, EP_IN = 0x01, 0x81


def main():
    seconds = float(sys.argv[1])
    out = sys.argv[2]
    speed = sys.argv[3] if len(sys.argv) > 3 else "auto"
    speed_map = {"ls": 0, "fs": 1, "hs": 2, "auto": 3}

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("device 1209:6688 not found")
    try:
        dev.get_active_configuration()
    except usb.core.USBError:
        dev.set_configuration()
    usb.util.claim_interface(dev, 0)

    raw = bytearray()
    st = Stream(payload_cb=lambda pl: raw.extend(pl))
    seq = [0]

    def send(cid, param):
        dev.write(EP_OUT, build_cmd(seq[0], cid, param), 200)
        deadline = time.time() + 1.0
        while time.time() < deadline and st.acks <= seq[0]:
            try:
                st.feed(bytes(dev.read(EP_IN, 65536, 100)))
            except usb.core.USBError:
                pass
        seq[0] += 1
        if st.acks < seq[0]:
            print("WARN: command 0x%02x not acknowledged" % cid, flush=True)

    send(CMD_ENABLE, 0)
    send(CMD_RESET, 1)
    send(CMD_SPEED, speed_map[speed])
    send(CMD_RESET, 0)
    mark = len(raw)
    send(CMD_ENABLE, 1)
    print("capturing %.0fs (speed=%s) ..." % (seconds, speed), flush=True)

    t_end = time.time() + seconds
    while time.time() < t_end:
        try:
            st.feed(bytes(dev.read(EP_IN, 262144, 500)))
        except usb.core.USBTimeoutError:
            continue

    send(CMD_ENABLE, 0)
    time.sleep(0.3)
    try:
        st.feed(bytes(dev.read(EP_IN, 262144, 300)))
    except usb.core.USBError:
        pass

    with open(out, "wb") as f:
        f.write(raw)
    print("wrote %s: %d B (bytes before enable: %d, blocks=%d acks=%d)"
          % (out, len(raw), mark, st.blocks, st.acks))


if __name__ == "__main__":
    main()
