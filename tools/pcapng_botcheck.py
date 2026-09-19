#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""pcapng_botcheck.py -- MSC/BOT sector-level completeness from an extcap pcapng.

For captures that are NOT the self-describing stress_pat.bin, this gives the
strongest available statement: for every completed READ10 command, did the
number of captured 512 B data packets equal the number of sectors requested?

BOT is strictly sequential (one outstanding CBW), so the CSW belongs to the
current CBW and data packets are attributed to it; a new CBW while one is
pending means the pending one never got its CSW (aborted -> host retries, which
show up as repeated (lba,n) pairs).  Note: duplicate CBW captures caused by
link-level retransmission show up as "aborted" with identical (lba,n); this
tool reports them separately from real shortfalls.

Usage: pcapng_botcheck.py <capture.pcapng>
Prints: commands, completed/aborted, requested vs captured sectors, missing,
        per-command shortfalls, unique LBA coverage.
"""
import struct, collections, sys

p = sys.argv[1]
d = open(p, 'rb').read()
off = 0
recs = []
while off + 12 <= len(d):
    t = struct.unpack_from('<I', d, off)[0]
    l = struct.unpack_from('<I', d, off + 4)[0]
    if l < 12 or off + l > len(d):
        break
    b = d[off + 8:off + l - 4]
    if t == 6:
        iid, tsh, tsl, cap, orig = struct.unpack_from('<IIIII', b, 0)
        if iid == 0:
            recs.append((((tsh << 32) | tsl), b[20:20 + cap]))
    off += l
recs.sort()

cmds = []
cur = None
for ts, pkt in recs:
    if len(pkt) == 34 and pkt[1:5] == b'USBC':
        if cur is not None:                 # previous never got a CSW -> aborted
            cur['aborted'] = True
            cmds.append(cur)
        cur = {'op': pkt[16], 'n': struct.unpack_from('>H', pkt, 23)[0] if pkt[16] == 0x28 else 0,
               'lba': struct.unpack_from('>I', pkt, 18)[0] if pkt[16] == 0x28 else -1,
               'data': 0, 'csw': False, 'aborted': False}
    elif len(pkt) == 16 and pkt[1:5] == b'USBS':
        if cur is not None:
            cur['csw'] = True
        cmds.append(cur) if cur is not None else None
        cur = None
    elif len(pkt) == 515 and cur is not None:
        cur['data'] += 1
if cur is not None:
    cur['aborted'] = True
    cmds.append(cur)

allc = [c for c in cmds if c is not None]
rd = [c for c in allc if c['op'] == 0x28]
comp = [c for c in rd if c['csw']]
abort = [c for c in rd if not c['csw']]
short = [c for c in comp if c['data'] != c['n']]
tot515 = sum(1 for _, p in recs if len(p) == 515)
print("file=%s" % p)
print("  CBW=%d (READ10 %d)  completed=%d aborted=%d  total 512B packets=%d"
      % (len(allc), len(rd), len(comp), len(abort), tot515))
req = sum(c['n'] for c in comp); got = sum(c['data'] for c in comp)
print("  completed: requested=%d captured=%d missing=%d (%.4f%%)"
      % (req, got, req - got, 100.0 * (req - got) / max(1, req)))
print("  completed cmds with data != n: %d" % len(short))
for c in short[:15]:
    print("     lba=%d n=%d got=%d" % (c['lba'], c['n'], c['data']))
print("  aborted commands=%d requested=%d sectors" % (len(abort), sum(c['n'] for c in abort)))
cov = set()
for c in rd:
    for k in range(c['n']):
        cov.add(c['lba'] + k)
print("  unique sectors requested (all READ10)=%d = %.2f MiB" % (len(cov), len(cov) * 512 / 1048576))
seen = collections.Counter((c['lba'], c['n']) for c in rd)
print("  repeated (lba,n) READ10 = %d" % sum(v - 1 for v in seen.values() if v > 1))
