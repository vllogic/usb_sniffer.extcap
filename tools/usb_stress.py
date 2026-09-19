#!/usr/bin/env python3
"""usb_stress.py — 采集链压力测试（U 盘真实流量 + 载荷完整性判读）

用途
----
在 Linux 下对 USB Sniffer 2 做多轮/压力测试，判断"硬件端"是否可靠：
  1. 在 U 盘上生成**带自校验标记**的图案文件（每 4096 B 一个 16 字节标记：
     magic + 该块的文件偏移 + 其反码 + magic 反码）；
  2. 一边用 O_DIRECT 持续读该文件（可多路并发）制造真实高密度 USB 流量，
     一边用 rawcap 抓包（默认 hs 模式，避免 auto 检测干扰）；
  3. 在抓到的原始流里搜索标记：统计**覆盖率（丢了多少）、反码校验失败（错位/位错）、
     顺序（乱序）**，并结合 FPGA 自身状态标志（crc_error/overflow/data_error 事件）
     与主机侧实际读到的字节数，给出该轮结论。

判据
----
* FPGA 标志：`overflow`/`data_error` 事件出现在**中段**（>1% 且 <99%）即为硬件端问题；
  出现在 0%/100% 属抓包起停瞬态（脚本会分开统计）。
* 图案覆盖率：与主机侧读到的字节数对比；覆盖率 ≈100% 且无校验失败 ⇒ 采集路径无损。

示例
----
  # 准备图案文件（一次即可）
  python3 extcap.usb_sniffer2/tools/usb_stress.py prep --dev /dev/sdb --mnt /mnt/udisk --mb 128
  # 一轮：hs 模式 + 4 路并发 O_DIRECT 读，抓 30 s
  python3 extcap.usb_sniffer2/tools/usb_stress.py run --mnt /mnt/udisk --secs 30 --readers 4 --speed hs
  # 矩阵：空闲/负载 × hs/auto 各 N 轮，输出汇总
  python3 extcap.usb_sniffer2/tools/usb_stress.py matrix --mnt /mnt/udisk --rounds 2
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
RAWCAP = os.path.join(HERE, "rawcap.py")
CHECKBITS = os.path.join(HERE, "checkbits.py")
MAGIC = bytes([0xA5, 0x5A, 0xA5, 0x5A])
REC = 4096                      # 标记周期
NAME = "stress_pat.bin"


# --------------------------------------------------------------------------- #
# 图案文件
# --------------------------------------------------------------------------- #
def make_block(off):
    inv = 0xFFFFFFFF ^ off
    body = bytearray(REC)
    body[0:4] = MAGIC
    body[4:8] = off.to_bytes(4, "little")
    body[8:12] = inv.to_bytes(4, "little")
    body[12:16] = bytes([0x5A, 0x5A, 0xA5, 0xA5])
    # 填充：随偏移变化的可辨识图案（也便于人眼/工具二次核对）
    for i in range(16, REC, 4):
        v = (off + i) & 0xFFFFFFFF
        body[i:i + 4] = v.to_bytes(4, "little")
    return bytes(body)


def cmd_prep(a):
    path = os.path.join(a.mnt, NAME)
    total = a.mb * 1024 * 1024
    print(f"[prep] 写入 {path} （{a.mb} MB，{total // REC} 个标记）...")
    t0 = time.time()
    with open(path, "wb", buffering=0) as f:      # buffering=0 → 直接落盘，避免缓存假象
        for off in range(0, total, REC):
            f.write(make_block(off))
    os.sync()
    dt = time.time() - t0
    print(f"[prep] 完成：{dt:.1f}s（{total/1e6/dt:.1f} MB/s），标记数 {total//REC}")


# --------------------------------------------------------------------------- #
# 采集 + 读盘负载
# --------------------------------------------------------------------------- #
def run_load(mnt, stop_flag, stats, deadline):
    """后台读盘（循环到 deadline）：O_DIRECT 顺序读图案文件，累计主机侧字节数。

    注意：必须用 O_DIRECT（iflag=direct），否则文件被页缓存命中后循环读不再产生
    USB 流量（这是本轮排查中踩过的坑）。
    """
    path = os.path.join(mnt, NAME)
    while time.time() < deadline:
        p = subprocess.run(["dd", f"if={path}", "of=/dev/null", "bs=1M", "iflag=direct"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        m = re.search(rb"(\d+) bytes", p.stderr or b"")
        if m:
            stats.setdefault("bytes", []).append(int(m.group(1)))


def cmd_run(a):
    out = a.out or os.path.join("/tmp/kilo", f"stress-{datetime.now().strftime('%H%M%S')}")
    os.makedirs(out, exist_ok=True)
    tag = a.tag or f"{a.speed}_{'load' if a.readers else 'idle'}"
    raw = os.path.join(out, f"{tag}.bin")
    res = {"tag": tag, "speed": a.speed, "readers": a.readers, "secs": a.secs,
           "raw": raw, "time": datetime.now().isoformat()}

    stats = {}
    from threading import Thread
    threads = []
    deadline = time.time() + a.secs + 5
    if a.readers > 0:
        for _ in range(a.readers):
            t = Thread(target=run_load, args=(a.mnt, stats, stats, deadline))
            t.start(); threads.append(t)
        time.sleep(0.3)                      # 让读盘先起来，避免抓包首段无流量

    print(f"[run:{tag}] 抓包 {a.secs}s（speed={a.speed}, readers={a.readers}）...")
    capcmd = (a.cap.split() if getattr(a, "cap", None) else ["python3", RAWCAP])
    capcmd += [str(a.secs), raw, a.speed]
    rc = subprocess.run(capcmd, capture_output=True, text=True)
    res["cap_cmd"] = " ".join(capcmd)
    for t in threads:
        t.join(timeout=180)
    res["rawcap_rc"] = rc.returncode
    res["raw_size"] = os.path.getsize(raw) if os.path.exists(raw) else 0
    res["host_bytes"] = sum(stats.get("bytes", []))

    # FPGA 标志（事件级 + 位置）
    cb = subprocess.run(["python3", CHECKBITS, raw], capture_output=True, text=True).stdout
    open(os.path.join(out, f"{tag}-checkbits.txt"), "w").write(cb)
    for k in ("crc_error", "overflow", "data_error"):
        m = re.search(rf"{k}\s+events=(\d+)\s+at=(\S+)", cb)
        res[k + "_events"] = int(m.group(1)) if m else 0
        res[k + "_at"] = m.group(2) if m else "-"
    m = re.search(r"frames=(\d+)", cb)
    res["frames"] = int(m.group(1)) if m else 0

    # 图案完整性（在抓到的原始流里找标记）
    cov, bad, order_bad, first_last = scan_markers(raw)
    res.update({"markers_found": cov["found"], "markers_expected": cov["expected"],
                "coverage_pct": cov["pct"], "bad_markers": bad, "order_violations": order_bad,
                "marker_span": first_last})
    print(f"[run:{tag}] 抓包 {res['raw_size']} B / 标记 {cov['found']}/{cov['expected']} "
          f"({cov['pct']:.1f}%) 校验失败 {bad} 乱序 {order_bad} | "
          f"FPGA 标志 crc={res['crc_error_events']} ovf={res['overflow_events']} "
          f"derr={res['data_error_events']} | 主机读 {res['host_bytes']} B")
    with open(os.path.join(out, f"{tag}.json"), "w") as f:
        json.dump(res, f, indent=2)
    return res


def scan_markers(path, max_hits=2_000_000):
    """在原始抓包流里搜索标记；返回 (覆盖率信息, 反码失败数, 乱序数, 偏移跨度)。"""
    data = open(path, "rb").read()
    offs = []
    bad = 0
    pos = 0
    while True:
        i = data.find(MAGIC, pos)
        if i < 0 or offs.__len__() >= max_hits:
            break
        if i + 16 <= len(data):
            o = int.from_bytes(data[i + 4:i + 8], "little")
            inv = int.from_bytes(data[i + 8:i + 12], "little")
            if (inv == (0xFFFFFFFF ^ o)) and data[i + 12:i + 16] == bytes([0x5A, 0x5A, 0xA5, 0xA5]):
                offs.append(o)
            else:
                bad += 1
        pos = i + 1
    uniq = sorted(set(offs))
    order_bad = sum(1 for a, b in zip(offs, offs[1:]) if b < a)
    expected = (max(uniq) // REC + 1) if uniq else 0
    pct = (len(uniq) / expected * 100.0) if expected else 0.0
    span = (uniq[0], uniq[-1]) if uniq else None
    return ({"found": len(uniq), "expected": expected, "pct": pct, "raw_hits": len(offs)}), bad, order_bad, span


def cmd_matrix(a):
    out = a.out or os.path.join("/tmp/kilo", f"stress-matrix-{datetime.now().strftime('%H%M%S')}")
    os.makedirs(out, exist_ok=True)
    rows = []
    plan = [("idle_hs", 0, "hs"), ("load_hs", a.readers, "hs")]
    if a.with_auto:
        plan += [("load_auto", a.readers, "auto")]
    for rnd in range(1, a.rounds + 1):
        for tag, readers, speed in plan:
            a.tag = f"r{rnd}_{tag}"; a.readers = readers; a.speed = speed
            a.out = out
            rows.append(cmd_run(a))
    print("\n[matrix] ================= SUMMARY =================")
    hdr = f"{'round/tag':16} {'frames':>9} {'rawMB':>7} {'markers':>13} {'cov%':>6} {'baderr':>6} {'ord':>4} {'crcEv':>5} {'ovfEv':>5} {'derrEv':>6}"
    print(hdr)
    for r in rows:
        print(f"{r['tag']:16} {r['frames']:9d} {r['raw_size']/1e6:7.2f} "
              f"{r['markers_found']:6d}/{r['markers_expected']:<6d} {r['coverage_pct']:6.1f} "
              f"{r['bad_markers']:6d} {r['order_violations']:4d} "
              f"{r['crc_error_events']:5d} {r['overflow_events']:5d} {r['data_error_events']:6d}")
    with open(os.path.join(out, "matrix.json"), "w") as f:
        json.dump(rows, f, indent=2)
    if rows and rows[0].get("cap_cmd"):
        print(f"[matrix] capture tool: {rows[0]['cap_cmd'].rsplit(' ', 3)[0]}")
    print(f"[matrix] 明细: {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prep"); p.add_argument("--mnt", required=True)
    p.add_argument("--mb", type=int, default=128); p.set_defaults(fn=cmd_prep)
    r = sub.add_parser("run"); r.add_argument("--mnt", required=True)
    r.add_argument("--secs", type=int, default=30); r.add_argument("--readers", type=int, default=4)
    r.add_argument("--speed", default="hs"); r.add_argument("--tag"); r.add_argument("--out")
    r.add_argument("--cap", help="capture tool (default: python3 rawcap.py); e.g. /tmp/kilo/usbcap")
    r.set_defaults(fn=cmd_run)
    m = sub.add_parser("matrix"); m.add_argument("--mnt", required=True)
    m.add_argument("--rounds", type=int, default=2); m.add_argument("--readers", type=int, default=4)
    m.add_argument("--secs", type=int, default=30)
    m.add_argument("--with-auto", action="store_true"); m.add_argument("--out")
    m.add_argument("--cap", help="capture tool (default: python3 rawcap.py)")
    m.set_defaults(fn=cmd_matrix)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
