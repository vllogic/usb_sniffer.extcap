#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate a fake UHSIF upstream stream from a reference pcapng sample.

The reference pcapngs (doc/*.pcapng) were produced by the upstream
usb-sniffer.  Their interface-0 EPB payloads are the *frame-layer output*:
the raw USB packet bytes without the 7-byte capture header, with the capture
timestamp stored in the EPB timestamp field.

To replay those samples through our frame layer we must reconstruct the
original capture byte stream: for every interface-0 EPB we synthesize the
matching 7-byte data header (toggle alternating, size, 20-bit 60 MHz
timestamp with overflow bits) and append the payload.  The reconstructed
stream is then wrapped into UHSIF blocks and prefixed with the five ACK
blocks the FPGA would emit for the init command sequence.

The output list of packets is deterministic: every injected frame produces
exactly one frame-layer EPB, so the replayed interface-0 packets are a
permutation of the sample's (folding reorders output, it never loses it).

Usage: make_fake_stream.py --speed <ls|fs|hs|auto> --in X.pcapng --out Y.bin
"""

import argparse
import struct
import sys

UHSIF_BLK_MAGIC16 = 0x6CC6      # w0[15:0] of an FPGA->PC block header
ACK_SEQ_START = 0
DATA_SEQ_START = 5          # 5 ACKs precede the data phase
CMD_WORDS = 1024            # max_payload_dwords default (4096 bytes)
ACK_COUNT = 5
CHANNEL_MASK = 1
CAPTURING = 1


def crc16(w1, w2, w3):
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB-first) over the 12
    header bytes in wire order (w1, w2, w3, each little-endian), matching
    uhsif.v crc16_hdr."""
    crc = 0xFFFF
    for i in range(12):
        w = (w1, w2, w3)[i >> 2]
        crc ^= ((w >> ((i & 3) * 8)) & 0xFF) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def block_header(chmask, capturing, words, seq):
    w1 = chmask & 0xFFF                          # {20'b0, channel_mask[11:0]}
    w2 = ((0 & 1) << 19) | ((capturing & 1) << 18) | ((0 & 3) << 16) | \
         (0 & 0x7FF) | 2                         # {12'b0,test,capturing,speed[1:0],11'b0,VER=2}
    w3 = ((seq & 0xFF) << 24) | ((words & 0xFFF) << 12)   # {seq[7:0],len[11:0],hdr3=0}
    w0 = (crc16(w1, w2, w3) << 16) | UHSIF_BLK_MAGIC16
    return struct.pack('<IIII', w0, w1, w2, w3)


def ns_to_ticks(ts_ns):
    """Smallest tick count (60 MHz) whose conversion back to ns is ts_ns.

    capture_ts = (ts_int | ts20) * 100 / 6 (integer division), so we need
    ticks with floor(ticks * 100 / 6) == ts_ns.
    """
    ticks = (ts_ns * 6) // 100
    while (ticks * 100) // 6 < ts_ns:
        ticks += 1
    return ticks


def status_header(ts20, toggle):
    """4-byte status frame header: no ts overflow, same line state.

    byte3 = 0 -> ls=0, vbus=0, trigger=0, speed=0.  These frames only carry
    timestamp state; they produce no output EPB.
    """
    b0 = (0x40 if toggle else 0) | (ts20 >> 16)
    b1 = (ts20 >> 8) & 0xFF
    b2 = ts20 & 0xFF
    b3 = 0
    return bytes([b0, b1, b2, b3])


def overflow_marker(toggle, ls=0, speed=0):
    """Synthesize a status frame carrying one pending timestamp overflow.

    Mirrors usb_capture.v: ts_overflow_r latches at timestamp == 0xFFFFF and
    the marker status frame is emitted at the *next* wrap period's 0xF0000
    point (header_ts_r samples timestamp_r at send time).  The low 20 bits
    must therefore be 0xF0000, NOT 0xFFFFF: with the PC-side 'add ts_int
    before computing ts' rule, a 0xFFFFF marker lands one wrap too late,
    making the following real frames appear to jump BACK ~16 ms, which trips
    the 2 s Periodic-update check as a (u64-wrapped) huge gap.

    The b3 field carries the live bus state like any other status frame
    (usb_capture.v status_data_w byte3 = status_w), so the current speed must
    be preserved -- a marker with speed=0 would make the PC flip the detected
    speed back to Low-Speed and break SOF folding.

    The frame layer adds 0x100000 to ts_int for every such marker, which is
    exactly what we need to reproduce the sample's absolute timestamps.
    """
    b0 = 0x10 | (0x40 if toggle else 0) | (0xF0000 >> 16)   # 0x10 = overflow
    b1 = (0xF0000 >> 8) & 0xFF
    b2 = 0xF0000 & 0xFF
    b3 = (ls & 0xF) | ((speed & 3) << 6)                     # live line state / speed
    return bytes([b0, b1, b2, b3])


def data_header(ts_ns, toggle, payload_len, ticks_in):
    """Synthesize the 7-byte capture data header for one frame."""
    ticks = ticks_in if ticks_in is not None else ns_to_ticks(ts_ns)
    ts20 = ticks & 0xFFFFF

    size = 7 + payload_len             # total frame size (header + payload)
    assert 7 <= size <= 1280, f"frame size {size} out of range"

    b0 = 0x80 | (0x40 if toggle else 0) | 0 | (ts20 >> 16)
    b1 = (ts20 >> 8) & 0xFF
    b2 = ts20 & 0xFF
    b3 = (size >> 8) & 0x07
    b4 = size & 0xFF
    b5 = 0                          # duration high (not stored in samples)
    b6 = 0                          # duration low
    return bytes([b0, b1, b2, b3, b4, b5, b6])


def parse_pcapng_interface0(path):
    """Return (linktype, [ (ts_ns, payload), ... ]) for interface-0 EPBs."""
    data = open(path, 'rb').read()
    off = 0
    epbs = []
    linktype = None
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, off)
        if btype == 1:
            lt = struct.unpack_from('<H', data, off + 8)[0]
            if linktype is None:
                linktype = lt
        elif btype == 6 and blen >= 28:
            iid = struct.unpack_from('<I', data, off + 8)[0]
            if iid == 0:
                tsh, tsl = struct.unpack_from('<II', data, off + 12)
                plen = struct.unpack_from('<I', data, off + 20)[0]
                if off + 28 + plen <= len(data):
                    epbs.append((((tsh << 32) | tsl), data[off + 28:off + 28 + plen]))
        if blen < 12:
            break
        off += blen
    return linktype, epbs


SPEED_TO_LINKTYPE = {'ls': 293, 'fs': 294, 'hs': 295, 'auto': 288}
SPEED_TO_IDX = {'ls': 0, 'fs': 1, 'hs': 2, 'auto': 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--speed', required=True, choices=['ls', 'fs', 'hs', 'auto'])
    parser.add_argument('--in', dest='fin', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()

    linktype, epbs = parse_pcapng_interface0(args.fin)

    if linktype != SPEED_TO_LINKTYPE[args.speed]:
        print(f"warning: sample linktype {linktype} does not match --speed {args.speed}",
              file=sys.stderr)

    # Reconstruct the capture byte stream.  Between data frames we inject
    # status frames that carry the pending-timestamp-overflow markers the
    # FPGA emits at each wrap period's 0xF0000 point (usb_capture.v:
    # ts_pending_r at timestamp_r == 0xf0000, header ts sampled at send
    # time), so the frame layer's ts_int accumulation reproduces the
    # sample's absolute timestamps.
    capture = bytearray()
    prev_markers = 0
    gidx = 0                       # global frame counter (markers + data)

    for ts_ns, payload in epbs:
        ticks = ns_to_ticks(ts_ns)

        # One marker per wrap whose 0xF0000 point this frame's tick has passed.
        # Inserting at the wrap boundary itself would put the marker ~16 ms
        # before its timestamp and make the following frames appear to jump
        # backwards (~16 ms regression pairs), which trips the PC-side 2 s
        # Periodic-update check via u64 wraparound.
        markers = max(0, (ticks - 0xF0000 - 1) >> 20)
        for _ in range(int(markers - prev_markers)):
            capture += overflow_marker(gidx & 1, speed=SPEED_TO_IDX[args.speed])
            gidx += 1
        prev_markers = markers

        hdr = data_header(ts_ns, gidx & 1, len(payload), ticks)
        capture += hdr
        gidx += 1
        capture += payload

    # Wrap into UHSIF data blocks.
    stream = bytearray()

    for i in range(ACK_COUNT):
        stream += block_header(CHANNEL_MASK, 0, 0, ACK_SEQ_START + i)

    seq = DATA_SEQ_START

    for off in range(0, len(capture), CMD_WORDS * 4):
        chunk = bytes(capture[off:off + CMD_WORDS * 4])
        pad = (-len(chunk)) % 4
        if pad:
            # Incomplete DATA header bytes (bit7 set, < 7 bytes) can never
            # complete into a frame, so no spurious packet is emitted.
            chunk += bytes([0x81, 0x00, 0x00][:pad])
        words = len(chunk) // 4
        stream += block_header(CHANNEL_MASK, CAPTURING, words, seq)
        stream += chunk
        seq += 1

    with open(args.out, 'wb') as f:
        f.write(stream)

    print(f"wrote {len(stream)} bytes: {ACK_COUNT} ACKs + {len(capture)} bytes of "
          f"capture stream ({len(epbs)} frames) in {(len(capture)+CMD_WORDS*4-1)//(CMD_WORDS*4)} "
          f"data blocks", file=sys.stderr)


if __name__ == '__main__':
    main()