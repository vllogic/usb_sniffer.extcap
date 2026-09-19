#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""checkbits.py -- single-bit corruption detector for the capture datapath.

Two independent checks over a rawcap.py stream:

1) anomaly: HS SOF payloads repeat for 8 consecutive microframes (the 11-bit
   frame number advances once per 8 microframes), so a frame that differs from
   BOTH its neighbours while they agree with each other is a one-frame glitch.
   This also catches bit flips the CRC5 check cannot see (e.g. in the PID byte).

2) downstream check: compares usb_capture's own crc_error flag (header byte3
   bit4) with an external CRC5 computation.  A frame whose flag is 0 while the
   CRC5 fails was corrupted AFTER the FPGA's capture-time CRC check, i.e. in the
   packer / staging FIFO / SRAM pool / small FIFO / UHSIF / CH32 / host path.

Flips are reported as the absolute bit position inside the packed 32-bit word
(byte lane * 8 + bit), which is the UHSIF DATA bus bit if the word is passed
through unchanged.

3) phase check (why it is here): every corruption analysed so far lands on a
   word index congruent to 3761 (mod 4096) -- i.e. once per 4096 payload words
   = 16 KiB of stream -- with the victim word bit fixed per FPGA build.  That
   phase is invariant not only across pool/pre-WIP builds but also across a 16x
   change of the capture packet FIFO depth, so the *trigger* is a periodic event
   outside the FPGA (the CH32's 4096-byte UHSIF IN buffer wrap, see
   docs/tasks/usb_capture_corruption_report.md §10.2) while the victim is an
   FPGA data-path bit.  Printing the phase keeps that invariant monitored: if a
   future change moves the phase, the trigger moved with it.

Usage: python3 checkbits.py <raw.bin> [start_offset]
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
    frames = []
    while off + 7 <= len(d):
        if d[off] & 0x80:
            size = ((d[off + 3] & 7) << 8) | d[off + 4]
            if size < 7 or size > 2048 or off + size > len(d):
                off += 1
                continue
            frames.append((off, d[off:off + 7], d[off + 7:off + size]))
            off += size
        else:
            off += 4

    three = [(o, h, p) for o, h, p in frames if len(p) == 3]
    print("%s: frames=%d 3-byte frames=%d" % (path, len(frames), len(three)))

    flip = collections.Counter()
    glitches = 0
    for k, (o, h, p) in enumerate(three):
        if k == 0 or k + 1 >= len(three):
            continue
        prev, nxt = three[k - 1][2], three[k + 1][2]
        # only SOF-family frames: real OUT/IN packets legitimately sit inside a
        # run of identical SOFs and would otherwise count as glitches
        if p[0] != 0xA5 or prev[0] != 0xA5 or nxt[0] != 0xA5:
            continue
        if p != prev and p != nxt and prev == nxt:
            glitches += 1
            for j in range(3):
                for b in range(8):
                    if ((p[j] ^ prev[j]) >> b) & 1:
                        flip[(((o + 7 + j) % 4) * 8 + b)] += 1
    print("isolated one-frame glitches: %d" % glitches)

    bad = downstream = 0
    phase = collections.Counter()
    for o, h, p in three:
        field = p[1] | (p[2] << 8)
        ok = crc5(bits_lsb(field & 0x7FF, 11)) == (field >> 11)
        flag = (h[3] >> 4) & 1
        if not ok:
            bad += 1
            if not flag:
                downstream += 1
                phase[(o // 4) % 4096] += 1
    print("SOF CRC5 failures: %d  (of which FPGA crc flag clean: %d)"
          % (bad, downstream))
    if phase:
        print("phase histogram (corrupted frame word index mod 4096 word = 16 KiB):")
        for ph, c in sorted(phase.items()):
            print("   word%%4096 = %4d : x%d" % (ph, c))
    if flip:
        print("glitch bit histogram (abs bit in packed word):")
        for ab, c in sorted(flip.items()):
            print("   word bit %2d (lane %d bit %d): x%d" % (ab, ab // 8, ab % 8, c))

    # ---- FPGA status flags (header byte 3) --------------------------------
    # Layout (see usb_capture.v): {2'b00, data_error, crc_error, overflow, size[10:8]}.
    # The flags are STICKY until the next packet commits, so the same event is
    # re-reported in every following status record: count 0->1 transitions
    # ("events"), not records, and report where they sit in the capture.
    flags = {"crc_error": 4, "overflow": 3, "data_error": 5}
    events = {k: [] for k in flags}
    prev = {k: 0 for k in flags}
    total = len(frames)
    for idx, (o, h, p) in enumerate(frames):
        for k, bit in flags.items():
            cur = (h[3] >> bit) & 1
            if cur and not prev[k]:
                events[k].append(idx / total * 100.0 if total else 0.0)
            prev[k] = cur
    print("FPGA status flag events (sticky flags counted as 0->1 transitions):")
    for k in ("crc_error", "overflow", "data_error"):
        pos = events[k]
        s = "none" if not pos else ("%.1f%%" % pos[0] if len(pos) == 1
                                    else "%.1f%%..%.1f%%" % (pos[0], pos[-1]))
        print("   %-10s events=%-4d at=%s" % (k, len(pos), s))


if __name__ == "__main__":
    main()
