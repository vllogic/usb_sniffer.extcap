#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""patcheck.py -- 4-byte (32-bit word) granularity integrity check of a raw
capture against the self-describing pattern file stress_pat.bin.

为什么需要它
------------
usb_stress.py 的 scan_markers() 只能做 4 KB（块标记）粒度：一个标记存在就认为
整个 4 KB 块在。0.5 KB 级的丢包（单个 USB 512 B 数据包被丢/被截断）只要不落在
块头就不会被发现。本工具做 **逐 32 位字** 校验，是分辨 0.5 KB 级丢包的判据。

图案的自描述性（关键）
----------------------
stress_pat.bin 每 4096 B 一块；块内文件偏移 F 处的 4 字节小端值 == F（块头 16 B
除外，是 magic+偏移+反码+magic 反码）。因此 **一个 512 B 的 USB 数据包自己就能
报出它在文件中的绝对偏移**：包内第 k 个字的值应为 B+4k（B 为包首字节的文件偏移），
少数几个字被破坏时用众数仍可稳健恢复 B。

因此本工具不需要依赖 USB 协议层/端点，不依赖标记命中，也不要求包按顺序（4 路并发
读同一文件时抓到的包来自 4 个互相交错的顺序流）：
  1. 流式解析 raw 采集流，取出全部 512 B 文件数据包（payload len==515, PID C3/4B）；
  2. 逐包恢复 B 并逐字与期望比对（错误字单独记录）；
  3. 用全部包覆盖区间求并集 => 采集窗口内**哪些 4 字节字从未出现**（真丢）；
     出现但不等于期望 => **错字**。
这正好区分「丢字」与「错字」两类，且粒度 = 4 字节。

用法
----
  python3 patcheck.py <raw.bin> [--json out.json] [--max-list N]

退出码：0 = 完美（无丢字、无错字、无未解析包）；1 = 有异常；2 = 无法读取。
"""
import argparse
import array
import collections
import json
import struct
import sys

MAGIC = bytes([0xA5, 0x5A, 0xA5, 0x5A])
MAGIC2 = bytes([0x5A, 0x5A, 0xA5, 0xA5])
MK0 = struct.unpack("<I", MAGIC)[0]          # 0x5AA55AA5
MK3 = struct.unpack("<I", MAGIC2)[0]         # 0xA5A55A5A
PACKET = 512
BLOCK = 4096
MAGIC_BYTES_LEN = 16


def marker_expected_bytes(base):
    return MAGIC + struct.pack("<I", base) + struct.pack("<I", (~base) & 0xFFFFFFFF) + MAGIC2


def recover_base(pkt):
    """恢复 512 B 包在文件中的绝对偏移 B；失败返回 None。

    常见路径（无损坏）：首字即 B，且次字/第三字为 B+4/B+8。
    标记包（B%4096==0）：首字是 magic，需先认标记。
    首字损坏：在包内找一对连续、相差 4 的字反推 B。
    """
    b0 = struct.unpack_from("<I", pkt, 0)[0]
    # 标记包：整块首字是 magic，偏移在第二个字
    if pkt[0:4] == MAGIC and pkt[12:16] == MAGIC2:
        o = struct.unpack_from("<I", pkt, 4)[0]
        if struct.unpack_from("<I", pkt, 8)[0] == ((~o) & 0xFFFFFFFF) and o % BLOCK == 0:
            return o
    # 普通包：首字 + 后两字一致
    if (b0 & 3) == 0 and b0 != MK0 and b0 != MK3 and b0 != ((~0) & 0xFFFFFFFF):
        if struct.unpack_from("<I", pkt, 4)[0] == ((b0 + 4) & 0xFFFFFFFF):
            if struct.unpack_from("<I", pkt, 8)[0] == ((b0 + 8) & 0xFFFFFFFF):
                return b0
    # 首字损坏：扫若干字找一对相邻且差 4
    for k in range(0, 128 - 2):
        v = struct.unpack_from("<I", pkt, 4 * k)[0]
        if v == MK0 or v == MK3:
            continue
        nxt = struct.unpack_from("<I", pkt, 4 * (k + 1))[0]
        if nxt == ((v + 4) & 0xFFFFFFFF):
            cand = (v - 4 * k) & 0xFFFFFFFF
            if cand % 4 == 0:
                return cand
    return None


def expected_for(pkt_base):
    """返回该包 512 B 的期望字节。"""
    if pkt_base % BLOCK == 0:
        head = marker_expected_bytes(pkt_base)
        body = array.array("I", range(pkt_base + 16, pkt_base + PACKET, 4)).tobytes()
        return head + body
    return array.array("I", range(pkt_base, pkt_base + PACKET, 4)).tobytes()


def bad_word_offsets(pkt, exp, pkt_base, limit):
    n = len(pkt) // 4
    ev = array.array("I")
    ev.frombytes(exp)
    pv = array.array("I")
    pv.frombytes(pkt)
    out = []
    for k in range(n):
        if pv[k] != ev[k]:
            out.append(pkt_base + 4 * k)
            if len(out) >= limit:
                break
    return out


def merge_intervals(starts):
    """starts: 排序好的区间起点列表（长度固定 PACKET）。返回覆盖字数。"""
    if not starts:
        return 0, []
    starts = sorted(starts)
    merged = []
    cs, ce = starts[0], starts[0] + PACKET
    for s in starts[1:]:
        e = s + PACKET
        if s <= ce:
            if e > ce:
                ce = e
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))
    covered_words = sum((e - s) // 4 for s, e in merged)
    return covered_words, merged


def stream_gaps(order, maxgap=1 << 20):
    """把抓包顺序里的包按「顺序流」重建（同一 reader 的连续读 = 一条流），
    统计每条流内部的缺口。这样即使多轮重复读（union 会掩盖丢包），仍能按流发现真丢。

    规则：包偏移 B 优先归入「next<=B 且最接近」的流；若 B-next 在 maxgap 内记为缺口，
    否则视为新流（例如 reader 回绕到文件开头）。
    返回 (gaps, streams)；gaps: [(start,end, order_index), ...]，streams: [next, ...]。
    """
    streams = []     # 每个元素 = 该流下一个期望的偏移
    gaps = []
    for oi, B in enumerate(order):
        best = -1
        for idx, nx in enumerate(streams):
            if nx <= B and (best < 0 or nx > streams[best]):
                best = idx
        if best >= 0 and (B - streams[best]) <= maxgap:
            if B > streams[best]:
                gaps.append((streams[best], B, oi))
            streams[best] = B + PACKET
        else:
            streams.append(B + PACKET)
    return gaps, streams


def slice_gaps(order, file_size, nslices):
    """读盘负载按不相交切片划分（每个 reader 独占 1/nslices 并循环）时的真丢检测。
    同一 reader 顺序读，其切片内偏移单调；跨 pass 回绕 => B 变小。分组无歧义。
    返回 (gaps, streams_count)；gaps: [(start,end,order_index), ...]。
    """
    size = max(1, file_size // nslices)
    last = {}
    gaps = []
    for oi, B in enumerate(order):
        q = min(B // size, nslices - 1)
        p = last.get(q)
        if p is None or B < p:
            last[q] = B
        elif B > p + PACKET:
            gaps.append((p + PACKET, B, oi))
            last[q] = B
        else:
            if B > p:
                last[q] = B
    return gaps, len(last)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--max-list", type=int, default=40)
    ap.add_argument("--slices", type=int, default=0,
                    help="读盘按 N 个不相交切片循环时, 用切片感知的缺口检测")
    ap.add_argument("--file-size", type=int, default=134217728)
    ap.add_argument("--max-bad-track", type=int, default=100000)
    a = ap.parse_args()

    f = open(a.raw, "rb")
    buf = b""
    CHUNK = 8 << 20

    starts = []                      # 所有 512B 数据包的起始文件偏移（用于区间并集）
    order = []                       # 同上，但保持抓包顺序（用于顺序流缺口重建）
    bad_words = collections.Counter()  # 错字：文件偏移 -> 次数
    unresolved = 0                   # 无法恢复基址的包
    bad_pkts = 0                     # 有错字的包数
    datapkts = 0
    data515 = 0
    marker_pkts = 0
    size_hist = collections.Counter()  # 数据类 PID 帧的 payload 长度分布
    truncated = []                   # 疑似被截断的数据包长度
    # FPGA 状态标志（粘滞到下个包）：按 0->1 跳变记事件，并记下发生时的数据包序号
    ev = []
    prev_flags = {"crc": 0, "ovf": 0, "derr": 0}

    raw_abs = 0                      # 当前 buf 起点在 raw 文件中的绝对偏移
    bad_pkt_raw = []                 # (raw_off, base, nbad) —— 用于区分起止瞬态与流中损坏
    while True:
        chunk = f.read(CHUNK)
        if not chunk:
            break
        buf = buf + chunk if buf else chunk
        i = 0
        n = len(buf)
        while i + 7 <= n:
            b0 = buf[i]
            if b0 & 0x80:
                size = ((buf[i + 3] & 7) << 8) | buf[i + 4]
                if size < 7 or size > 1280:
                    i += 1
                    continue
                if i + size > n:
                    break
                fl = buf[i + 3]
                for name, bit in (("crc", 4), ("ovf", 3), ("derr", 5)):
                    cur = (fl >> bit) & 1
                    if cur and not prev_flags[name]:
                        ev.append((name, datapkts, i))
                    prev_flags[name] = cur
                pay_off = i + 7
                pay_len = size - 7
                if pay_len >= 1:
                    pid = buf[pay_off]
                    if pid in (0xC3, 0x4B):
                        size_hist[pay_len] += 1
                        if pay_len == 515:
                            pkt = buf[pay_off + 1:pay_off + 513]
                            data515 += 1
                            if pkt[0:4] == MAGIC and pkt[12:16] == MAGIC2 and \
                               struct.unpack_from('<I', pkt, 8)[0] == \
                               ((~struct.unpack_from('<I', pkt, 4)[0]) & 0xFFFFFFFF):
                                marker_pkts += 1
                            base = recover_base(pkt)
                            # Non-pattern content makes recover_base return a
                            # bogus huge offset whose expected array would
                            # overflow 2^32; treat it as unresolved instead of
                            # crashing (this tool assumes stress_pat.bin).
                            if base is None or base + PACKET > 0xFFFFFFFF:
                                unresolved += 1
                            else:
                                datapkts += 1
                                starts.append(base)
                                order.append(base)
                                exp = expected_for(base)
                                if pkt != exp:
                                    bad_pkts += 1
                                    nb = 0
                                    for off in bad_word_offsets(pkt, exp, base, a.max_bad_track):
                                        bad_words[off] += 1
                                        nb += 1
                                    bad_pkt_raw.append((raw_abs + i, base, nb))
                        elif pay_len not in (16, 34):   # 16=CSW 34=CBW
                            truncated.append(pay_len)
                i += size
            else:
                if i + 4 > n:
                    break
                i += 4
        raw_abs += i
        buf = buf[i:]
    f.close()
    raw_total = raw_abs + len(buf)
    # 起止瞬态豁免（按 raw 流位置 ≤1% / ≥99% 归类）
    bad_start = sum(1 for ro, _, _ in bad_pkt_raw if ro < 0.01 * raw_total)
    bad_end = sum(1 for ro, _, _ in bad_pkt_raw if ro > 0.99 * raw_total)
    bad_mid = bad_pkts - bad_start - bad_end
    bad_start_words = sum(nb for ro, _, nb in bad_pkt_raw if ro < 0.01 * raw_total)
    bad_end_words = sum(nb for ro, _, nb in bad_pkt_raw if ro > 0.99 * raw_total)

    covered_words, merged = merge_intervals(starts)
    if starts:
        span_lo, span_hi = min(starts), max(starts) + PACKET
        span_words = (span_hi - span_lo) // 4
    else:
        span_lo = span_hi = span_words = 0
    missing_words = span_words - covered_words
    # 缺口区间（相对文件偏移），用于区分「采集起始前缀」与「流中真丢包」
    gaps = []
    prev_end = span_lo
    for s, e in merged:
        if s > prev_end:
            gaps.append((prev_end, s))
        prev_end = max(prev_end, e)
    gaps.sort(key=lambda g: g[0])
    gap_words = sum((e - s) // 4 for s, e in gaps)

    if a.slices > 0:
        sgap, nstreams = slice_gaps(order, a.file_size, a.slices)
    else:
        sgap, streams = stream_gaps(order, span_hi)
        nstreams = len(streams)
    sgap.sort(key=lambda g: g[0])
    sgap_words = sum((e - s) // 4 for s, e, _ in sgap)
    ecnt = collections.Counter(n for n, _, _ in ev)
    # 中段事件（起止各 1% 豁免）
    lo_oi, hi_oi = 0.01 * datapkts, 0.99 * datapkts
    ev_mid = collections.Counter(n for n, oi, _ in ev if lo_oi < oi < hi_oi)

    res = {
        "raw": a.raw,
        "data_packets": datapkts,
        "unresolved_packets": unresolved,
        "bad_packets": bad_pkts,
        "span_file_offsets": [span_lo, span_hi],
        "span_words": span_words,
        "covered_words": covered_words,
        "missing_words": missing_words,
        "gap_words": gap_words,
        "gap_count": len(gaps),
        "gap_ranges_sample": [[s, e] for s, e in gaps[:a.max_list]],
        "stream_gap_count": len(sgap),
        "stream_gap_words": sgap_words,
        "stream_gap_ranges_sample": [list(t) for t in sgap[:a.max_list]],
        "stream_count": nstreams,
        "fpga_events_total": {k: ecnt.get(k, 0) for k in ("crc", "ovf", "derr")},
        "fpga_events_mid": {k: ev_mid.get(k, 0) for k in ("crc", "ovf", "derr")},
        "wrong_words": len(bad_words),
        "bad_packets_mid": bad_mid,
        "bad_packets_start": bad_start,
        "bad_packets_end": bad_end,
        "raw_total_bytes": raw_total,
        "bad_packet_raw_positions": [[ro, b, nb] for ro, b, nb in bad_pkt_raw[:a.max_list]],
        "wrong_word_offsets_sample": sorted(bad_words)[:a.max_list],
        "truncated_non_cbw_csw": len(truncated),
        "truncated_sizes_top": collections.Counter(truncated).most_common(8),
        "data_payload_len_hist": dict(sorted(size_hist.items())),
    }
    print("raw: %s" % a.raw)
    print("  512B data packets parsed : %d  (unresolved=%d)" % (datapkts, unresolved))
    print("  capture file span        : [%d, %d)  %d words"
          % (span_lo, span_hi, span_words))
    print("  covered words            : %d" % covered_words)
    print("  MISSING words (4B)       : %d   (%.6f%% of span)"
          % (missing_words, 100.0 * missing_words / span_words if span_words else 0.0))
    print("  gaps (interior holes)    : %d  total %d words (%.6f%%)"
          % (len(gaps), gap_words, 100.0 * gap_words / span_words if span_words else 0.0))
    for s, e in gaps[:a.max_list]:
        print("    gap [%d, %d)  %d B  %d words" % (s, e, e - s, (e - s) // 4))
    print("  stream gaps (real drops) : %d  total %d words (%.6f%%)  [streams=%d]"
          % (len(sgap), sgap_words, 100.0 * sgap_words / span_words if span_words else 0.0,
             nstreams))
    ev_by_datapkt = {}
    for name, oi, rawi in ev:
        ev_by_datapkt.setdefault(oi, []).append(name)
    for s, e, oi in sgap[:a.max_list]:
        near = []
        for k in range(max(0, oi - 200), oi + 1):
            for nm in ev_by_datapkt.get(k, []):
                near.append("%s@%d" % (nm, k))
        print("    stream gap [%d, %d)  %d B  %d words  before pkt#%d  flags_near=%s"
              % (s, e, e - s, (e - s) // 4, oi, ",".join(near[-6:]) or "-"))
    print("  FPGA flag events         : crc=%d ovf=%d derr=%d  (mid-stream: crc=%d ovf=%d derr=%d)"
          % (ecnt.get("crc", 0), ecnt.get("ovf", 0), ecnt.get("derr", 0),
             ev_mid.get("crc", 0), ev_mid.get("ovf", 0), ev_mid.get("derr", 0)))
    print("  WRONG words (4B)         : %d   (in %d packets: mid=%d start=%d end=%d)"
          % (len(bad_words), bad_pkts, bad_mid, bad_start, bad_end))
    if bad_words:
        print("    first wrong offsets    : %s"
              % ", ".join(str(o) for o in sorted(bad_words)[:a.max_list]))
    if bad_pkt_raw:
        print("    bad packets (raw_off/base/nwords): %s"
              % ", ".join("(%d,%d,%d)" % t for t in bad_pkt_raw[:a.max_list]))
    if truncated:
        print("  truncated data frames    : %d  sizes=%s"
              % (len(truncated), collections.Counter(truncated).most_common(8)))
    print("  data payload len hist    : %s"
          % ", ".join("%d:%d" % kv for kv in sorted(size_hist.items())[:12]))

    if a.json_out:
        with open(a.json_out, "w") as jf:
            json.dump(res, jf, indent=2)
    # 只有切片/整文件模式的顺序流重建才可靠（多 reader 读同一区间的重叠流会误报），
    # 因此 sgap 仅在 --slices>0 时参与判定；其余模式只作参考输出。
    sgap_fatal = (sgap_words if a.slices > 0 else 0)
    flag_mid = sum(ev_mid.values())
    if data515 > 0 and marker_pkts == 0:
        print("  VERDICT                  : NOT A PATTERN CAPTURE "
              "(%d 512B packets, 0 valid block markers) -- content is not stress_pat.bin" % data515)
        return 1
    strict = (missing_words == 0 and len(bad_words) == 0 and unresolved == 0
              and sgap_fatal == 0 and flag_mid == 0)
    mid_ok = (missing_words == 0 and bad_mid == 0 and unresolved == 0
              and sgap_fatal == 0 and flag_mid == 0)
    if strict:
        verdict = ("PERFECT (0 missing words, 0 wrong words, 0 stream gaps, "
                   "0 mid-stream flags)")
    elif mid_ok:
        verdict = ("MID-STREAM CLEAN (only start/end transients: "
                   "wrong start=%d pkts/%d words end=%d pkts/%d words; "
                   "total flag events crc=%d ovf=%d derr=%d all at edges)"
                   % (bad_start, bad_start_words, bad_end, bad_end_words,
                      ecnt.get("crc", 0), ecnt.get("ovf", 0), ecnt.get("derr", 0)))
    else:
        verdict = "ANOMALY"
    print("  VERDICT                  : %s" % verdict)
    return 0 if strict else 1


if __name__ == "__main__":
    sys.exit(main())
