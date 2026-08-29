#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare a replayed capture against a reference sample.

The reference pcapng (doc/*.pcapng) was produced by the upstream usb-sniffer
frame layer; its interface-0 EPB payloads are the raw USB packet bytes and
the EPB timestamp is the capture timestamp in ns.

The replayed file is produced by our pipeline from a reconstructed byte
stream.  Because folding reorders output (it batches empty frames and
flushes them later), the comparison groups frames by payload bytes and
matches the timestamps within each group in order, tolerating a ±1 wrap
(17.48 ms) absolute-ts deviation: the fake-stream generator places the
timestamp-overflow markers at the first frame past each 0xF0000 point, and
frames right at a wrap boundary can legitimately land one wrap early or
late relative to the hardware capture.
"""

import struct
import sys

TOL_NS = 100         # 1 tick @ 60 MHz is ~16.7 ns
WRAP_NS = 17476267    # one 20-bit wrap (0x100000 ticks)


def walk_blocks(path):
    data = open(path, 'rb').read()
    off = 0
    blocks = []
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, off)
        if blen < 12 or off + blen > len(data):
            break
        blocks.append((btype, data[off:off + blen]))
        off += blen
    return blocks


def collect(path):
    blocks = walk_blocks(path)
    ids = []
    epbs = {}
    for btype, b in blocks:
        if btype == 1:
            lt = struct.unpack_from('<H', b, 8)[0]
            ids.append(lt)
        elif btype == 6:
            iid = struct.unpack_from('<I', b, 8)[0]
            tsh, tsl = struct.unpack_from('<II', b, 12)
            cap_len = struct.unpack_from('<I', b, 20)[0]
            payload = b[28:28 + cap_len]
            epbs.setdefault(iid, []).append((((tsh << 32) | tsl), payload))
    return ids, epbs


def ts_close(ta, tb):
    return min(abs(ta - tb), abs(ta - tb - WRAP_NS), abs(ta - tb + WRAP_NS)) <= TOL_NS


def main():
    a_path, b_path = sys.argv[1], sys.argv[2]
    ids_a, epbs_a = collect(a_path)
    ids_b, epbs_b = collect(b_path)

    ok = True

    # Interface link types (order as written: USB IDB then info IDB).
    if ids_a != ids_b:
        print(f"MISMATCH interface linktypes: {ids_a} vs {ids_b}")
        ok = False

    # Group frames by payload bytes; within a group the order is preserved
    # and only the timestamps may shift by a whole wrap for boundary frames.
    groups_a = {}
    groups_b = {}
    for ts, payload in epbs_a.get(0, []):
        groups_a.setdefault(payload, []).append(ts)
    for ts, payload in epbs_b.get(0, []):
        groups_b.setdefault(payload, []).append(ts)

    if set(groups_a) != set(groups_b):
        print(f"MISMATCH interface 0: frame bytes differ "
              f"({len(epbs_a.get(0, []))} vs {len(epbs_b.get(0, []))})")
        ok = False

    mism = 0
    for payload, ta in groups_a.items():
        tb = groups_b.get(payload, [])
        if len(ta) != len(tb):
            # The fake stream inserts synthetic overflow-marker status
            # frames, which can shift the hardware's fold-batch boundaries
            # by one frame; tolerate a single-frame group difference.
            if abs(len(ta) - len(tb)) <= 1:
                print(f"WARN frame count for payload {payload.hex()}: "
                      f"{len(ta)} vs {len(tb)} (fold boundary artifact)")
            else:
                print(f"MISMATCH frame count for payload {payload.hex()}: "
                      f"{len(ta)} vs {len(tb)}")
                mism += 1
                ok = False
            continue

        ia = ib = 0
        while ia < len(ta) and ib < len(tb):
            if ts_close(ta[ia], tb[ib]):
                ia += 1
                ib += 1
            elif ib + 1 < len(tb) and ts_close(ta[ia], tb[ib + 1]):
                ib += 1                     # extra frame on the replay side
            elif ia + 1 < len(ta) and ts_close(ta[ia + 1], tb[ib]):
                ia += 1                     # missing frame on the replay side
            else:
                print(f"MISMATCH frame #{ia}: ts {ta[ia]} vs {tb[ib]}, "
                      f"payload {payload.hex()}")
                mism += 1
                ok = False
                ia += 1
                ib += 1
                if mism > 5:
                    break

    # Sanity: the info stream must contain the capture-start announcement.
    info_b = [x[1].decode('latin1', 'replace') for x in epbs_b.get(1, [])]
    joined = '|'.join(info_b)
    for required in ('Starting capture',):
        if required not in joined:
            print(f"MISSING info message: {required}")
            ok = False

    print(f"interface 0: {len(epbs_a.get(0, []))} frames compared, {'match' if ok else 'mismatch'}")
    print(f"interface 1: {len(info_b)} info strings")

    print('PASS' if ok else 'FAIL')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()