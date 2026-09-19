#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""checkcap.py -- capture quality metrics from a rawcap.py stream.

Parses the capture frame layer (protocol.md section 4):
  data frame : byte0 bit7=1, 7-byte header, size = ((b3&7)<<8)|b4, payload size-7
  status     : byte0 bit7=0, 4 bytes

Reports, over all 3-byte-payload (SOF) frames:
  * PID validity   : USB PIDs carry a nibble and its complement
  * SOF CRC5       : CRC5 (x^5+x^2+1, init 0x1f, LSB first) over the 11-bit frame
                     number must match the 5 bits above it in the payload field

Usage: python3 checkcap.py <raw.bin> [start_offset]
"""
import collections
import sys


def crc5(bits):
    crc = 0x1F
    for b in bits:
        c = (crc & 1) ^ b
        crc >>= 1
        if c:
            crc ^= 0x14
    return crc ^ 0x1F


def bits_lsb(v, n):
    return [(v >> i) & 1 for i in range(n)]


def main():
    path = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    d = open(path, "rb").read()[start:]
    off = 0
    tot = crc_ok = pid_ok = 0
    pidc = collections.Counter()
    ex = []
    while off + 7 <= len(d):
        b0 = d[off]
        if b0 & 0x80:
            hdr = d[off:off + 7]
            size = ((hdr[3] & 7) << 8) | hdr[4]
            if size < 7 or size > 2048 or off + size > len(d):
                off += 1
                continue
            pay = d[off + 7:off + size]
            if size == 10 and len(pay) >= 3:
                pidc[pay[0]] += 1
                if (pay[0] & 0x0F) == ((~pay[0] >> 4) & 0x0F):
                    pid_ok += 1
                field = pay[1] | (pay[2] << 8)
                if crc5(bits_lsb(field & 0x7FF, 11)) == (field >> 11):
                    crc_ok += 1
                elif len(ex) < 4:
                    ex.append(pay.hex(" "))
                tot += 1
            off += size
        else:
            off += 4

    print("%s (start=%d): 3-byte frames=%d" % (path, start, tot))
    print("  PID valid  : %d/%d (%.1f%%)" % (pid_ok, tot, 100.0 * pid_ok / max(1, tot)))
    print("  SOF CRC5 ok: %d/%d (%.1f%%)" % (crc_ok, tot, 100.0 * crc_ok / max(1, tot)))
    print("  top bytes0 : %s" % [(hex(k), v) for k, v in pidc.most_common(5)])
    print("  CRC5-fail examples: %s" % ex)


if __name__ == "__main__":
    main()
