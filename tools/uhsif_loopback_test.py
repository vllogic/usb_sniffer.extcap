#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""UHSIF link loopback test via the FPGA bandwidth-test (TEST_MODE) stream.

Drives the CH32H417 zero-semantics bridge directly: sends UHSIF commands on
EP1 OUT and reads raw upstream blocks on EP1 IN, bypassing the capture
interpret layer (counter-fill payloads are not valid capture frames).

Verifies, over a fixed measurement window:
  * every block header magic 6CC6 and crc16 (CRC-16/CCITT-FALSE),
  * block sequence continuity across ACK/data blocks,
  * counter payload continuity (each u32 strictly increments),
  * upstream throughput (bytes/s of block+payload traffic).

Usage: python3 uhsif_loopback_test.py [--seconds 10] [--speed hs]
Exit code 0 on success, 1 on any violation.
"""

import argparse
import struct
import sys
import time

import usb.core
import usb.util

VID, PID = 0x1209, 0x6688
EP_OUT, EP_IN = 0x01, 0x81
CMD_MAGIC = 0xC7F3
BLK_MAGIC = 0x6CC6

CMD_RESET, CMD_ENABLE, CMD_SPEED, CMD_TEST = 0x01, 0x02, 0x03, 0x04


def crc16(w1, w2, w3):
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB-first) over the 12
    header bytes in wire order (w1, w2, w3, each little-endian)."""
    crc = 0xFFFF
    for i in range(12):
        w = (w1, w2, w3)[i >> 2]
        crc ^= ((w >> ((i & 3) * 8)) & 0xFF) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_cmd(seq, cid, param):
    w1 = ((seq & 0xFF) << 8) | cid
    w2 = param
    w3 = 0
    w0 = (crc16(w1, w2, w3) << 16) | CMD_MAGIC
    return struct.pack("<IIII", w0, w1, w2, w3)


class Stream:
    def __init__(self, payload_cb=None):
        self.payload_cb = payload_cb  # called with each data-block payload
        self.buf = b""
        self.aligned = False     # True once a block boundary is established
        self.last_seq = None
        self.counter = None      # expected next counter word (None until first)
        self.blocks = 0
        self.acks = 0
        self.bytes_payload = 0
        self.errors = []

    def feed(self, data):
        # Port of extcap stream.c (STREAM_SCAN / STREAM_BLOCK): the v2 header
        # carries the magic in w0[15:0], i.e. at byte offset 0 of the header,
        # so candidates are validated with crc16 (+reserved bits + payload
        # range) before being committed; bogus magic inside payloads is
        # skipped bytewise instead of corrupting the frame walk.
        self.buf += data
        while True:
            if not self.aligned:
                i = self.buf.find(struct.pack("<H", BLK_MAGIC))
                if i < 0:
                    self.buf = self.buf[-3:]
                    return
                hdr = i
                if len(self.buf) < hdr + 16:
                    self.buf = self.buf[hdr:]
                    return
                w0, w1, w2, w3 = struct.unpack_from("<IIII", self.buf, hdr)
                plen = (w3 >> 12) & 0xFFF
                if ((w0 & 0xFFFF) != BLK_MAGIC or (w0 >> 16) != crc16(w1, w2, w3)
                        or (w1 & 0xFFFFF000)
                        or (plen != 0 and not (1 <= plen <= 4092))):
                    self.buf = self.buf[hdr + 1:]
                    continue
                self.buf = self.buf[hdr:]
                self.aligned = True
            else:
                if len(self.buf) < 16:
                    self.aligned = False
                    self.buf = self.buf[-3:]
                    return
                w0, w1, w2, w3 = struct.unpack_from("<IIII", self.buf, 0)
                plen = (w3 >> 12) & 0xFFF
                if ((w0 & 0xFFFF) != BLK_MAGIC or (w0 >> 16) != crc16(w1, w2, w3)
                        or (w1 & 0xFFFFF000)
                        or (plen != 0 and not (1 <= plen <= 4092))):
                    self.errors.append(
                        f"invalid header at aligned pos w0={w0:#010x}, resync")
                    self.aligned = False
                    self.buf = self.buf[1:]
                    continue
                total = 16 + 4 * plen
                if len(self.buf) < total:
                    return

            w0, w1, w2, w3 = struct.unpack_from("<IIII", self.buf, 0)
            plen = (w3 >> 12) & 0xFFF
            seq = (w3 >> 24) & 0xFF
            if self.last_seq is not None and seq != ((self.last_seq + 1) & 0xFF):
                self.errors.append(f"seq jump {self.last_seq} -> {seq}")
            self.last_seq = seq

            total = 16 + 4 * plen
            payload = self.buf[16:total]
            if plen == 0:
                self.acks += 1
            else:
                self.blocks += 1
                self.bytes_payload += len(payload)
                if self.payload_cb is not None:
                    self.payload_cb(payload)
                words = struct.unpack(f"<{len(payload)//4}I", payload)
                for w in words:
                    if self.counter is not None and w != self.counter:
                        self.errors.append(
                            f"counter discontinuity: got {w:#010x}, exp {self.counter:#010x}")
                        self.counter = None
                        break
                    self.counter = (w + 1) & 0xFFFFFFFF
            self.buf = self.buf[total:]

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
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--speed", default="auto", choices=["ls", "fs", "hs", "auto"])
    args = ap.parse_args()

    speed_map = {"ls": 0, "fs": 1, "hs": 2, "auto": 3}
    dev = find_device()
    if dev is None:
        sys.exit("device 1209:6688 not found")
    dev.set_configuration()
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except NotImplementedError:
        pass
    usb.util.claim_interface(dev, 0)

    st = Stream()
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

    # Startup order mirrors docs/protocol.md / src/main.c capture_init_cmds:
    # Enable 0 -> Reset 1 -> Speed -> Reset 0.  Enable 1 is intentionally
    # omitted: TEST_MODE alone opens the upload gate (tx_allow = test) and
    # keeps the stream pure counter-fill without ULPI capture blocks.
    send(CMD_ENABLE, 0)
    send(CMD_RESET, 1)
    send(CMD_SPEED, speed_map[args.speed])
    send(CMD_RESET, 0)
    send(CMD_TEST, 1)          # counter-fill upload starts (tx_allow = test)

    print(f"streaming for {args.seconds:.0f}s ...")
    t_end = time.time() + args.seconds
    n_read = 0
    while time.time() < t_end:
        try:
            data = bytes(dev.read(EP_IN, 262144, 500))
        except usb.core.USBTimeoutError:
            continue
        n_read += len(data)
        st.feed(data)

    send(CMD_TEST, 0)          # stop upload
    time.sleep(0.3)
    try:
        st.feed(bytes(dev.read(EP_IN, 262144, 300)))
    except usb.core.USBError:
        pass

    dt = args.seconds
    print(f"blocks={st.blocks} acks={st.acks} payload={st.bytes_payload} B "
          f"raw={n_read} B  throughput={st.bytes_payload/dt/1e6:.1f} MB/s "
          f"(payload) / {n_read/dt/1e6:.1f} MB/s (raw)")
    if st.errors:
        print(f"FAIL ({len(st.errors)} errors):")
        for e in st.errors[:20]:
            print("  " + e)
        reset_device(dev)        # 端点恢复（下行计数只增不减，见 reset_device 注释）
        return 1
    print("PASS")
    reset_device(dev)            # 端点恢复，保证下一次会话可直接运行
    return 0


if __name__ == "__main__":
    sys.exit(main())
