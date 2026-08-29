#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Feature-level offline tests for the interpret layer.

Builds hand-crafted UHSIF capture streams and asserts the exact output:
folding of empty frames, LS keep-alive synthesis, trigger gating, capture
limit, hardware buffer overflow reporting and periodic updates.

Usage: feature_tests.py <path-to-usb_sniffer_ch32> <workdir>
"""

import os
import subprocess
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_fake_stream import (  # noqa: E402
    block_header, overflow_marker, ACK_COUNT, ACK_SEQ_START, DATA_SEQ_START,
    CMD_WORDS, CHANNEL_MASK, CAPTURING,
)

BUS = os.path.abspath(sys.argv[1])
WORK = os.path.abspath(sys.argv[2])


def data_frame(tickval, toggle, payload, overflow=False, crc_err=False, dterr=False):
    """7-byte data header + payload.  Returns full frame bytes."""
    ts20 = tickval & 0xFFFFF
    size = 7 + len(payload)
    assert 7 <= size <= 1280
    b0 = 0x80 | (0x40 if toggle else 0) | (ts20 >> 16)
    b1 = (ts20 >> 8) & 0xFF
    b2 = ts20 & 0xFF
    b3 = (size >> 8) & 0x07
    if dterr:
        b3 |= 0x20
    if crc_err:
        b3 |= 0x10
    if overflow:
        b3 |= 0x08
    b4 = size & 0xFF
    b5, b6 = 0, 0
    return bytes([b0, b1, b2, b3, b4, b5, b6]) + payload


def status_frame(tickval, toggle, ls, vbus=0, trigger=0, speed=0, overflow=False):
    """4-byte status frame header."""
    ts20 = tickval & 0xFFFFF
    b0 = (0x40 if toggle else 0) | (0x10 if overflow else 0) | (ts20 >> 16)
    b1 = (ts20 >> 8) & 0xFF
    b2 = ts20 & 0xFF
    b3 = (ls & 0xF) | ((1 if vbus else 0) << 4) | ((1 if trigger else 0) << 5) | ((speed & 3) << 6)
    return bytes([b0, b1, b2, b3])


class CapBuilder:
    """Builds a capture byte stream with automatic timestamp-overflow markers."""

    def __init__(self):
        self.b = bytearray()
        self.prev_markers = 0
        self.gidx = 0
        self.speed = 0     # current bus speed; markers carry the live state

    def _sync(self, tickval):
        # Mirrors make_fake_stream: one marker per wrap whose 0xF0000 point
        # this tick has passed; at the wrap boundary itself the marker would
        # land ~16 ms before its timestamp and regress the frame ts.  The
        # marker carries the current speed so the PC-side speed detection is
        # not flipped back to Low-Speed (which would break SOF folding).
        markers = max(0, (tickval - 0xF0000 - 1) >> 20)
        while markers > self.prev_markers:
            self.b += overflow_marker(self.gidx & 1, speed=self.speed)
            self.gidx += 1
            self.prev_markers += 1

    def data(self, tickval, payload, **kw):
        self._sync(tickval)
        self.b += data_frame(tickval, self.gidx & 1, payload, **kw)
        self.gidx += 1

    def status(self, tickval, **kw):
        if 'speed' in kw:
            self.speed = kw['speed']
        self._sync(tickval)
        self.b += status_frame(tickval, self.gidx & 1, **kw)
        self.gidx += 1

    def pad_to_words(self, min_words=1):
        """Append benign status frames so the payload covers at least
        min_words (the v2 protocol allows any block length 1..4092 words).

        The filler frames keep a constant line state so they emit no extra
        output beyond the initial status summary."""
        need = min_words * 4 - len(self.b)
        tick = max(1, self.gidx * 1000)
        while need > 0:
            self.status(tick, ls=0, speed=0)
            tick += 1000
            need -= 4

    def bytes(self):
        return bytes(self.b)


def wrap(cap_builder):
    """Wrap capture bytes into a UHSIF stream (5 ACKs + data blocks)."""
    cap_builder.pad_to_words()
    capture = cap_builder.bytes()
    out = bytearray()
    for i in range(ACK_COUNT):
        out += block_header(CHANNEL_MASK, 0, 0, ACK_SEQ_START + i)
    seq = DATA_SEQ_START
    for off in range(0, len(capture), CMD_WORDS * 4):
        chunk = bytes(capture[off:off + CMD_WORDS * 4])
        pad = (-len(chunk)) % 4
        if pad:
            chunk += bytes([0x81, 0x00, 0x00][:pad])
        words = len(chunk) // 4
        out += block_header(CHANNEL_MASK, CAPTURING, words, seq)
        out += chunk
        seq += 1
    return bytes(out)


def run(args, stream, out):
    path = os.path.join(WORK, 'feat.bin')
    with open(path, 'wb') as f:
        f.write(stream)
    cmd = [BUS, '--replay', path, '--fifo', out] + args
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'replay failed: {r.stderr}')


def collect(out):
    data = open(out, 'rb').read()
    ids, epbs = [], {}
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, off)
        if btype == 1:
            ids.append(struct.unpack_from('<H', data, off + 8)[0])
        elif btype == 6 and blen >= 28:
            iid = struct.unpack_from('<I', data, off + 8)[0]
            tsh, tsl = struct.unpack_from('<II', data, off + 12)
            cap_len = struct.unpack_from('<I', data, off + 20)[0]
            epbs.setdefault(iid, []).append((((tsh << 32) | tsl), data[off + 28:off + 28 + cap_len]))
        if blen < 12:
            break
        off += blen
    return ids, epbs


def check(name, cond, detail=''):
    print(f'[{"ok  " if cond else "FAIL"}] {name}' + (f'  {detail}' if not cond and detail else ''))
    if not cond:
        raise AssertionError(name)


def infos(epbs):
    return ''.join(x[1][14:].decode('latin1') for x in epbs.get(1, []))


# --------------------------------------------------------------------------
def test_folding():
    """Empty-frame folding: IN/NAK accumulate and flush in order; repeated
    SOFs collapse into a counted group (upstream semantics)."""
    # Scenario 1: SOF+IN+NAK accumulate; the following data frame flushes
    # them in order without a count message (count == 0).
    c = CapBuilder()
    t = 1000
    for _ in range(3):
        for pid in (b'\xa5\x00\x01', b'\x69\x00\x01', b'\x5a'):
            c.data(t, pid)
            t += 100
        c.data(t, b'\xc3\x00\x11\x22')
        t += 100

    out = os.path.join(WORK, 'fold.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)

    data0 = [x[1] for x in epbs.get(0, [])]
    expected = [b'\xa5\x00\x01', b'\x69\x00\x01', b'\x5a', b'\xc3\x00\x11\x22'] * 3
    check('folding: folded batch flushed in order', data0 == expected, str(len(data0)))

    # Scenario 2: a run of SOFs collapses (each SOF resets the fold buffer);
    # the flush messages carries the run length.
    c = CapBuilder()
    t = 1000
    for _ in range(2):
        for pid in (b'\xa5\x00\x01', b'\xa5\x00\x02', b'\xa5\x00\x03'):
            c.data(t, pid)
            t += 100
        c.data(t, b'\xc3\x00\x11\x22')
        t += 100

    out = os.path.join(WORK, 'fold_sof.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)

    data0 = [x[1] for x in epbs.get(0, [])]
    expected = [b'\xa5\x00\x03', b'\xc3\x00\x11\x22'] * 2     # only the last SOF survives
    check('folding: SOF run collapses to last SOF', data0 == expected, f'{len(data0)}')

    info = infos(epbs)
    check('folding: "Folded 2 empty frames" reported 2x',
          info.count('Folded 2 empty frames') == 2, info)


def test_keepalive_ls():
    """SE0 -> J3 transition of ~1.2 us is a keep-alive event."""
    c = CapBuilder()
    t0 = 100_000
    c.status(t0, ls=0, speed=0)                  # SE0
    c.status(t0 + (1200 * 6 // 100), ls=12, speed=0)   # +1.2 us, J3
    c.data(t0 + 100, b'\xc3\x01\x02\x03')        # flush

    out = os.path.join(WORK, 'ka.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)
    check('keepalive: "Keep-alive" present (fold)', 'Keep-alive' in infos(epbs), infos(epbs))

    out = os.path.join(WORK, 'ka_nofold.pcapng')
    run(['--speed', 'ls'], wrap(c), out)
    _, epbs = collect(out)
    check('keepalive: "Keep-alive" present (no fold)', 'Keep-alive' in infos(epbs), infos(epbs))


def test_overflow():
    """A data frame with the overflow flag is reported and still written."""
    c = CapBuilder()
    c.data(1000, b'\xc3\x01\x02\x03', overflow=True)

    out = os.path.join(WORK, 'ovf.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)
    check('overflow: "Hardware buffer overflow" reported', 'Hardware buffer overflow' in infos(epbs), infos(epbs))
    check('overflow: packet still written', len(epbs.get(0, [])) == 1)


def test_periodic_update():
    """A >2 s gap in packet timestamps triggers a periodic update."""
    c = CapBuilder()
    c.data(60_000, b'\xc3\x01\x02\x03')                       # 1 ms
    c.data(156_000_000, b'\xc3\x04\x05\x06')                  # 2.6 s later

    out = os.path.join(WORK, 'periodic.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)
    check('periodic: "Periodic update" present', 'Periodic update' in infos(epbs), infos(epbs))


def test_periodic_heartbeat():
    """Regression: a status-frame-only stream (57.2 Hz) must emit exactly ONE
    'Periodic update' per 2 s of silence, not one per frame.

    The v2 port forgot to refresh capture_last_ts on every EPB/info write, so
    the 2 s timeout degenerated to firing on every status frame (~17.5 ms),
    which also broke folding (stop_folding on every capture_info)."""
    c = CapBuilder()
    t = 60_000
    for _ in range(180):                            # 180 status frames @ 17.5 ms
        c.status(t, ls=0, speed=0)                  #  ~3.15 s of bus idle
        t += 1_050_000

    out = os.path.join(WORK, 'heartbeat.pcapng')
    run(['--speed', 'ls', '--fold'], wrap(c), out)
    _, epbs = collect(out)
    info = infos(epbs)
    n = info.count('Periodic update')
    check('heartbeat: exactly one "Periodic update" in 3.15 s idle', n == 1, f'{n} updates')


def test_fold_survives_timeout():
    """Regression: continuous foldable SOFs must accumulate to the fold limit
    (1000 @ FS) and flush on their own, untouched by the 2 s Periodic-update
    timeout; the timeout must not fire while folding produces output."""
    c = CapBuilder()
    c.status(60_000, ls=0, speed=1)                 # 1 ms: FS detected
    t = 120_000
    for _ in range(2200):                           # 2200 SOFs @ 1 kHz (2.2 s)
        c.data(t, b'\xa5\x00\x01')                  # FS folds SOFs
        t += 60_000
    c.data(t, b'\xc3\x01\x02\x03')                  # real packet flushes the tail

    out = os.path.join(WORK, 'fold_timeout.pcapng')
    run(['--speed', 'fs', '--fold'], wrap(c), out)
    _, epbs = collect(out)
    info = infos(epbs)
    check('fold: limit batch "Folded 1000 empty frames" 2x', info.count('Folded 1000 empty frames') == 2, info)
    check('fold: tail batch "Folded 199 empty frames"', 'Folded 199 empty frames' in info, info)
    check('fold: no "Periodic update" while folding', 'Periodic update' not in info, info)


def test_trigger_falling():
    """Falling edge trigger gates the capture."""
    c = CapBuilder()
    c.status(60, ls=0, trigger=1, speed=0)     # high
    c.data(120, b'\x69\x01\x02')               # dropped (still disabled)
    c.status(180, ls=0, trigger=0, speed=0)    # falling edge
    c.data(240, b'\x69\x03\x04')               # captured
    c.data(300, b'\x69\x05\x06')               # captured

    out = os.path.join(WORK, 'trig.pcapng')
    run(['--speed', 'ls', '--fold', '--trigger', 'falling'], wrap(c), out)
    _, epbs = collect(out)
    data0 = [x[1] for x in epbs.get(0, [])]
    check('trigger: pre-trigger frames dropped', len(data0) == 2, f'{len(data0)} frames')
    info = infos(epbs)
    check('trigger: waiting then starting reported',
          'Waiting for a trigger' in info and 'Starting capture' in info, info)


def test_capture_limit():
    """--limit stops the capture after N frames."""
    c = CapBuilder()
    for i in range(5):
        c.data(1000 + i * 100, b'\xd2')

    out = os.path.join(WORK, 'limit.pcapng')
    run(['--speed', 'ls', '--fold', '--limit', '3'], wrap(c), out)
    _, epbs = collect(out)
    data0 = epbs.get(0, [])
    check('limit: only 3 frames captured', len(data0) == 3, f'{len(data0)} frames')
    check('limit: "Capture limit reached" reported', 'Capture limit reached' in infos(epbs), infos(epbs))


def test_stream_resync():
    """A corrupted block header in the middle of the stream is detected; the
    stream layer reports the loss and recovers on the next valid block."""
    c1 = CapBuilder()                          # data block 1 (frame A)
    c1.data(1000, b'\xc3\x01\x02\x03')
    c2 = CapBuilder()                          # data block 2 (frame B)
    c2.data(2000, b'\xc3\x04\x05\x06')

    stream = bytearray()
    for i in range(ACK_COUNT):
        stream += block_header(CHANNEL_MASK, 0, 0, ACK_SEQ_START + i)

    # Pad a capture segment to whole 32-bit words (incomplete DATA header
    # bytes can never complete into a frame), like wrap() does.
    def word_pad(seg):
        pad = (-len(seg)) % 4
        return seg + bytes([0x81, 0x00, 0x00][:pad])

    # Block 1: valid magic half-word, but a flipped crc16 bit (a realistic
    # single-bit corruption of w0).  w0 = {crc16[31:16], magic 6CC6[15:0]},
    # so on the wire the crc16 occupies bytes 2-3; flip byte 2.
    seg1 = word_pad(c1.bytes())
    bad = block_header(CHANNEL_MASK, CAPTURING, len(seg1) // 4, DATA_SEQ_START)
    bad = bytes([bad[0], bad[1], bad[2] ^ 0x01, bad[3]]) + bad[4:]
    stream += bad + seg1

    # A fake header candidate (magic half-word matches, checksum does not):
    # the scanner must skip it and keep hunting.
    stream += struct.pack('<I', (0x1234 << 16) | 0x6CC6)

    # Block 2: fully valid (a fresh block, seq continues).
    seg2 = word_pad(c2.bytes())
    stream += block_header(CHANNEL_MASK, CAPTURING, len(seg2) // 4, DATA_SEQ_START + 1)
    stream += seg2

    out = os.path.join(WORK, 'resync.pcapng')
    run(['--speed', 'ls', '--fold'], bytes(stream), out)
    _, epbs = collect(out)
    info = infos(epbs)
    check('stream: link loss reported', 'link packet loss' in info, info)
    # Frame A is lost together with the corrupted block; frame B survives.
    check('stream: capture continues after resync',
          len(epbs.get(0, [])) == 1, f'{len(epbs.get(0, []))} frames')


# --------------------------------------------------------------------------
def main():
    os.makedirs(WORK, exist_ok=True)
    tests = [
        test_folding,
        test_keepalive_ls,
        test_overflow,
        test_periodic_update,
        test_periodic_heartbeat,
        test_fold_survives_timeout,
        test_trigger_falling,
        test_capture_limit,
        test_stream_resync,
    ]
    for t in tests:
        t()
    print('ALL FEATURE TESTS PASSED')


if __name__ == '__main__':
    main()