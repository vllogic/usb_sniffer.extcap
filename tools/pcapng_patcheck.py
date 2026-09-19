#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""pcapng_patcheck.py -- 4-byte (32-bit word) pattern integrity check directly
from a Wireshark extcap pcapng (the plugin's native output).

Method: MSC layer.  BOT is strictly one outstanding command, so each 512 B data
packet following a READ10 carries exactly LBA, LBA+1, ... .  That places every
sector at its true disk offset.  The pattern file is located on the disk by
auto-detecting its LBA base L0 from a valid block marker (marker at file offset
F stores F, so L0 = disk_sector - F/512).  Then EVERY word is checked:

  * body word at file offset F  ==  F
  * block header (F % 4096 < 16): magic | F-0 | ~o | magic2 at m=0,4,8,12
  * missing words : file sectors inside the captured span that never arrived
  * duplicate sectors (retransmissions/retries) reported, not errors

Usage: pcapng_patcheck.py <capture.pcapng> [--file-size N] [--json out.json]
Exit: 0 perfect, 1 anomaly / not the pattern, 2 parse error.
"""
import argparse, array, collections, json, struct, sys

MAGIC = bytes([0xA5, 0x5A, 0xA5, 0x5A])
MAGIC2 = bytes([0x5A, 0x5A, 0xA5, 0xA5])
MK0 = struct.unpack("<I", MAGIC)[0]
MK3 = struct.unpack("<I", MAGIC2)[0]
SECTOR = 512
BLOCK = 4096


def read_if0(path):
    d = open(path, "rb").read()
    off, n, out = 0, len(d), []
    while off + 12 <= n:
        bt = struct.unpack_from("<I", d, off)[0]
        bl = struct.unpack_from("<I", d, off + 4)[0]
        if bl < 12 or off + bl > n:
            break
        if bt == 6:
            b = d[off + 8:off + bl - 4]
            iid, tsh, tsl, cap, orig = struct.unpack_from("<IIIII", b, 0)
            if iid == 0:
                out.append(b[20:20 + cap])
        off += bl
    return out


def marker_at(data, file_off):
    """Return True if the 16 bytes at file_off form a valid block header."""
    if file_off % BLOCK != 0:
        return False
    if data[0:4] != MAGIC or data[12:16] != MAGIC2:
        return False
    o = struct.unpack_from("<I", data, 4)[0]
    return struct.unpack_from("<I", data, 8)[0] == ((~o) & 0xFFFFFFFF)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcapng")
    ap.add_argument("--file-size", type=int, default=134217728)
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--max-list", type=int, default=30)
    a = ap.parse_args()

    sectors = {}                       # lba -> 512 B data
    dup = 0
    cur = None
    cmds = collections.Counter()
    for pkt in read_if0(a.pcapng):
        n = len(pkt)
        if n == 34 and pkt[1:5] == b'USBC':
            op = pkt[16]
            cur = {'op': op, 'lba': struct.unpack_from(">I", pkt, 18)[0] if op == 0x28 else -1,
                   'n': struct.unpack_from(">H", pkt, 23)[0] if op == 0x28 else 0, 'i': 0}
            cmds[op] += 1
        elif n == 16 and pkt[1:5] == b'USBS':
            cur = None
        elif n == 515 and cur is not None and cur['op'] == 0x28:
            sec = cur['lba'] + cur['i']; cur['i'] += 1
            if sec in sectors:
                dup += 1
            else:
                sectors[sec] = pkt[1:513]

    # locate the pattern file's LBA base from valid markers (vote)
    votes = collections.Counter()
    for sec, data in sectors.items():
        # a marker can only start a block; test the sector head and, if the
        # sector is block-aligned within the file, that is the marker
        for off in (0,):
            if data[0:4] == MAGIC and data[12:16] == MAGIC2:
                o = struct.unpack_from("<I", data, 4)[0]
                if struct.unpack_from("<I", data, 8)[0] == ((~o) & 0xFFFFFFFF):
                    if o % SECTOR == 0:
                        votes[sec - o // SECTOR] += 1
    if not votes:
        print("no valid block markers in reconstructed content -> not stress_pat.bin")
        return 1
    L0, hits = votes.most_common(1)[0]
    file_sectors = a.file_size // SECTOR

    missing_sectors = []
    wrong = []
    present = 0
    for f in range(file_sectors):
        sec = L0 + f
        data = sectors.get(sec)
        base = f * SECTOR
        if data is None:
            missing_sectors.append(f)
            continue
        present += 1
        if base % BLOCK == 0:
            exp = bytearray(16)
            struct.pack_into("<I", exp, 0, MK0)
            struct.pack_into("<I", exp, 4, base)
            struct.pack_into("<I", exp, 8, (~base) & 0xFFFFFFFF)
            struct.pack_into("<I", exp, 12, MK3)
            exp += array.array("I", range(base + 16, base + SECTOR, 4)).tobytes()
        else:
            exp = array.array("I", range(base, base + SECTOR, 4)).tobytes()
        if data != exp:
            ev = array.array("I"); ev.frombytes(exp)
            gv = array.array("I"); gv.frombytes(data)
            for k in range(SECTOR // 4):
                if gv[k] != ev[k]:
                    wrong.append(base + 4 * k)

    print("pcapng: %s" % a.pcapng)
    print("  commands:", {hex(k): v for k, v in cmds.items()})
    print("  pattern file LBA base L0=%d (marker votes=%d)" % (L0, hits))
    print("  file sectors=%d  captured=%d (%.3f%%)  duplicate sectors=%d"
          % (file_sectors, present, 100.0 * present / file_sectors, dup))
    print("  MISSING sectors=%d -> MISSING words(4B)=%d"
          % (len(missing_sectors), len(missing_sectors) * (SECTOR // 4)))
    print("  WRONG words(4B)=%d" % len(wrong))
    if wrong:
        print("    first: %s" % ", ".join(str(x) for x in wrong[:a.max_list]))
    if missing_sectors:
        runs = []
        s = p = missing_sectors[0]
        for x in missing_sectors[1:]:
            if x == p + 1:
                p = x
            else:
                runs.append((s, p)); s = p = x
        runs.append((s, p))
        print("    missing runs (file sectors): %s%s"
              % (runs[:10], " ..." if len(runs) > 10 else ""))
    ok = (not wrong and present == file_sectors)
    print("  VERDICT: %s" % ("PERFECT (whole file, 0 missing, 0 wrong)" if ok
                             else ("ALL CAPTURED WORDS CORRECT (%d missing sectors)"
                                   % len(missing_sectors) if not wrong else "ANOMALY")))
    if a.json_out:
        json.dump({"L0": L0, "present": present, "missing": len(missing_sectors),
                   "wrong": len(wrong), "dup": dup}, open(a.json_out, "w"), indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
