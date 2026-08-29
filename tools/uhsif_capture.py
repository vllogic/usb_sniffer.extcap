#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Live USB capture dump via the UHSIF bridge (capture-mode stream).

Initialises the sniffer per docs/protocol.md (Enable 0 -> Reset 1 -> Speed ->
Reset 0 -> Enable 1), streams EP1 IN blocks, decodes the capture frame layer
(data frames: 7-byte header + raw USB packet bytes; status frames: 4-byte
header) and prints a per-PID / per-transaction summary so captured USB traffic
(e.g. device enumeration against a bus host) can be eyeballed without
Wireshark.  Raw payload bytes are saved with --raw for offline analysis.

Usage: python3 uhsif_capture.py [--seconds 15] [--speed auto] [--raw out.bin]
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import usb.core  # noqa: E402
import usb.util  # noqa: E402

from uhsif_loopback_test import (  # noqa: E402
    Stream, build_cmd, CMD_RESET, CMD_ENABLE, CMD_SPEED,
)

VID, PID = 0x1209, 0x6688
EP_OUT, EP_IN = 0x01, 0x81

PID_NAMES = {
    0xE1: "OUT", 0x69: "IN", 0xA5: "SOF", 0x2D: "SETUP",
    0xC3: "DATA0", 0x4B: "DATA1", 0xD2: "ACK", 0x5A: "NAK",
    0x1E: "STALL", 0x78: "SPLIT", 0xB4: "PING", 0x3C: "PRE",
}

DESC_NAMES = {1: "DEVICE", 2: "CONFIG", 3: "STRING", 4: "IFACE",
              5: "ENDPOINT", 6: "DEV_QUAL", 7: "OTHER_SPEED", 8: "IFACE_POWER"}


class Frames:
    """Splits the payload byte stream into capture frames (docs protocol.md §4)."""

    def __init__(self):
        self.buf = b""
        self.counts = {}
        self.tokens = {}
        self.examples = []
        self.status = 0
        self.errors = []

    def feed(self, data):
        self.buf += data
        while True:
            if len(self.buf) < 4:
                self.buf = self.buf[-3:]
                return
            if self.buf[0] & 0x80:                      # data frame, 7-byte hdr
                if len(self.buf) < 7:
                    return
                size = ((self.buf[3] & 0x07) << 8) | self.buf[4]
                if not (7 <= size <= 1280):
                    self.errors.append(f"bad data-frame size {size}")
                    self.buf = self.buf[1:]
                    continue
                if len(self.buf) < size:
                    return
                ts = ((self.buf[0] & 0x0F) << 16) | (self.buf[1] << 8) | self.buf[2]
                pkt = self.buf[7:size]
                self._packet(ts, pkt)
                self.buf = self.buf[size:]
            else:                                       # status frame, 4-byte
                self.status += 1
                self.buf = self.buf[4:]

    def _packet(self, ts, pkt):
        pid = pkt[0]
        name = PID_NAMES.get(pid, f"pid={pid:02x}")
        self.counts[name] = self.counts.get(name, 0) + 1
        if pid in (0x2D, 0x69, 0xE1) and len(pkt) >= 2:  # tokens: addr/ep
            addr = pkt[1] & 0x7F
            ep = (pkt[1] >> 7) | ((pkt[2] & 0x07) << 1)
            self.tokens[f"{name} a{addr:02x} ep{ep}"] = \
                self.tokens.get(f"{name} a{addr:02x} ep{ep}", 0) + 1
        if pid == 0x2D and len(pkt) >= 9:               # decode SETUP
            bmrt, req = pkt[1], pkt[2]
            wval = pkt[3] | (pkt[4] << 8)
            widx = pkt[5] | (pkt[6] << 8)
            wlen = pkt[7] | (pkt[8] << 8)
            if req == 0x06:
                desc = (f"GET_DESCRIPTOR {DESC_NAMES.get(wval >> 8, wval >> 8)}"
                        f" idx={widx} len={wlen}")
            elif req == 0x05:
                desc = f"SET_ADDRESS addr={wval}"
            elif req == 0x09:
                desc = f"SET_CONFIGURATION cfg={wval}"
            elif req == 0x08:
                desc = "GET_CONFIGURATION"
            elif req == 0x00:
                desc = "GET_STATUS"
            else:
                desc = f"req={req:02x} val={wval:#06x} idx={widx:#06x} len={wlen}"
            self.tokens[f"SETUP({bmrt:02x}) {desc}"] = \
                self.tokens.get(f"SETUP({bmrt:02x}) {desc}", 0) + 1
            if len(self.examples) < 16:
                self.examples.append(
                    (f"{ts * 100 / 6 / 1e6:.6f}s", f"{bmrt:02x}{req:02x}" + pkt[3:9].hex()))

def reset_device(dev, delay_ms=500):
    """会话后端点恢复: 经 EP0 vendor request E2 软复位设备（同 iap_cli reset）。

    背景: 固件 UHSIF 下行计数 WR_COMM.total 只增不减（WCH 例程未实现
    UHSIF 中断处理/回调调用者），多次会话累计 >= DEF_UHSIF_TXBUF_CNT(8) 后
    EP1_RX 链停止（stop=1），EP1 OUT 永久停滞，只能靠设备复位恢复。
    会话收尾主动复位，确保下一次会话开箱即用。
    """
    try:
        dev.ctrl_transfer(0x40, 0xE2, delay_ms, 0, b"", 1000)
    except usb.core.USBError:
        pass


def find_device(retries=3, wait=2.0):
    """打开设备；若正处于 (上轮会话) 软复位重枚举期则等待重试。"""
    for _ in range(max(1, retries)):
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is not None:
            return dev
        time.sleep(wait)
    return None




def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=15.0)
    ap.add_argument("--speed", default="auto", choices=["ls", "fs", "hs", "auto"])
    ap.add_argument("--raw", default="", help="save raw payload bytes to file")
    args = ap.parse_args()

    speed_map = {"ls": 0, "fs": 1, "hs": 2, "auto": 3}
    dev = find_device()
    if dev is None:
        sys.exit("device 1209:6688 not found")
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)

    raw = bytearray()
    fr = Frames()
    st = Stream(payload_cb=lambda pl: (raw.extend(pl), fr.feed(bytes(pl))))
    cmd_seq = 0

    def send(cid, param):
        nonlocal cmd_seq
        dev.write(EP_OUT, build_cmd(cmd_seq, cid, param), 200)
        deadline = time.time() + 1.0
        while time.time() < deadline and st.acks <= cmd_seq:
            try:
                st.feed(bytes(dev.read(EP_IN, 65536, 100)))
            except usb.core.USBError:
                pass
        cmd_seq += 1
        if st.acks < cmd_seq:
            sys.exit(f"command 0x{cid:02x} not acknowledged")

    send(CMD_ENABLE, 0)
    send(CMD_RESET, 1)
    send(CMD_SPEED, speed_map[args.speed])
    send(CMD_RESET, 0)
    send(CMD_ENABLE, 1)
    print(f"capturing for {args.seconds:.0f}s ...", flush=True)

    t_end = time.time() + args.seconds
    while time.time() < t_end:
        try:
            st.feed(bytes(dev.read(EP_IN, 262144, 500)))
        except usb.core.USBTimeoutError:
            continue

    send(CMD_ENABLE, 0)                                 # stop capture
    time.sleep(0.3)
    try:
        st.feed(bytes(dev.read(EP_IN, 262144, 300)))
    except usb.core.USBError:
        pass

    print(f"\n=== capture summary ({args.seconds:.0f}s) ===")
    for k, v in sorted(fr.counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k:12s} {v}")
    print("transactions:")
    for k, v in sorted(fr.tokens.items(), key=lambda kv: -kv[1]):
        print(f"  {k:48s} {v}")
    if fr.examples:
        print("examples (SETUP):")
        for ts, hx in fr.examples:
            print(f"  {ts}  {hx}")
    if fr.errors:
        print("frame errors:", fr.errors[:8])
    print(f"status_frames={fr.status} blocks={st.blocks} acks={st.acks} "
          f"payload={st.bytes_payload} B")
    if args.raw:
        with open(args.raw, "wb") as f:
            f.write(raw)
        print(f"raw payload saved to {args.raw} ({len(raw)} B)")

    reset_device(dev)   # 端点恢复：软复位，保证下一次会话可直接运行
    return 0


if __name__ == "__main__":
    sys.exit(main())