// SPDX-License-Identifier: BSD-3-Clause
// usbcap.c — 高速主机抓包工具（USB Sniffer 2 上行原始流）
//
// 与 tools/rawcap.py 等价但为 C + libusb-1.0 异步实现：
//   * 同时在途 N 个批量 IN 传输（默认 8×256 KiB），不做"一次一个"的同步往返；
//   * 上行块解析在完成回调里就地完成（magic/CRC-16/块长/seq），只把 payload 落盘；
//   * 输出与 rawcap.py 相同（UHSIF 数据块的 payload 逐字节拼接），可直接用
//     checkbits.py / checkcap.py / usb_stress.py 判读。
//
// usbcap_fast —— 性能最优化版本（用于排查设备侧溢出）
//   * **无超时**：libusb_fill_bulk_transfer(..., timeout=0) —— 无限等待，URB 永不因超时被
//     cancel（超时会取消 URB，设备侧在途数据随之丢失，是排查中的干扰源）；
//   * 大量 URB（默认 32）在途，尺寸可调（默认 128 KiB），彻底覆盖 host 取数延迟；
//   * 大缓冲输出（默认 8 MiB，write() 直写），避免小 fwrite 抖动；--null 或 --stats 可完全不落盘；
//   * **在 C 里直接做采集帧走查**，统计 FPGA 状态标志的**事件数**（crc_error/overflow/
//     data_error 的 0->1 跳变）与总记录数 —— 排查溢出无需磁盘、无需 Python 后处理。
//
// 用法:
//   ./usbcap_fast <seconds> <out.bin|-> [auto|ls|fs|hs] [--urbs N] [--urb-size BYTES]
//                 [--no-write]        # 只统计不落盘
// 退出时打印: wrote <out>: <N> B (bytes before enable: X, blocks=B acks=A)
//
// 协议（见 tools/uhsif_loopback_test.py / src/cmd.c）:
//   下行命令 4 字: W0={crc16(w1,w2,w3),0xC7F3}, W1=(seq<<8)|cid, W2=param, W3=0
//   上行块 16B 头 + payload: W0={crc16(w1,w2,w3),0x6CC6}, plen=W3[23:12], seq=W3[31:24]
//     plen==0 -> ACK；plen>0 -> 数据块（payload = plen 个 32bit 字）
//   初始化序列: ENABLE0 -> RESET1 -> SPEED -> RESET0 -> ENABLE1

#include <libusb-1.0/libusb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define VID 0x1209
#define PID 0x6688
#define EP_OUT 0x01
#define EP_IN 0x81

#define CMD_MAGIC 0xC7F3u
#define BLK_MAGIC 0x6CC6u
#define CMD_RESET 0x01
#define CMD_ENABLE 0x02
#define CMD_SPEED 0x03
#define CMD_TEST  0x04
#define CMD_UPLOAD 0x20

#define URBS_MAX 64
#define URB_SIZE_MAX (4u * 1024u * 1024u)

static libusb_context *ctx;
static libusb_device_handle *dev;
static FILE *out;
static uint64_t bytes_payload, bytes_before_enable;
static unsigned blocks, acks, hdr_errors, seq_jumps;
static int last_seq = -1;
static int stopping;
static unsigned urbs, urb_size;
static uint8_t *urb_buf[URBS_MAX];
static struct libusb_transfer *urb_tr[URBS_MAX];

// --------------------------------------------------------------------------
// 异步落盘：回调线程绝不能做阻塞 write()。宿主写盘若在事件循环线程里做，
// 一次 write() 的停顿（脏页回写/分配回收）会让 libusb 事件循环停摆，URB 不再
// 重提交 -> 设备侧回压 -> FPGA 采集 FIFO overflow（实测：不落盘 ovfEv≈1–32，
// 落 tmpfs ≈0.5–1.5k，落磁盘 ≈3–8k，同负载同工具）。这里改为：回调把 payload
// 拷进 1 MiB 环形缓冲，独立写线程落盘，事件循环只做内存拷贝。
// --------------------------------------------------------------------------
#define WQ_SLOTS 64
#define WQ_CHUNK (1u << 20)
static uint8_t *wq_buf[WQ_SLOTS];
static size_t   wq_len[WQ_SLOTS];
static int      wq_head, wq_tail, wq_count;
static uint8_t *free_buf[WQ_SLOTS];      // 预分配缓冲池（热路径零 malloc/free）
static int      free_n;
static pthread_mutex_t wq_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  wq_nonempty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  wq_nonfull  = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  wq_free     = PTHREAD_COND_INITIALIZER;
static int      wq_stop, write_error;
static uint8_t *cur_buf;
static size_t   cur_len;
static pthread_t writer_tid;

static void wq_init(void)
{
    for (int i = 0; i < WQ_SLOTS; i++) free_buf[i] = malloc(WQ_CHUNK);
    free_n = WQ_SLOTS;
}

static void buf_put_free(uint8_t *b)
{
    pthread_mutex_lock(&wq_mu);
    free_buf[free_n++] = b;
    pthread_cond_signal(&wq_free);
    pthread_mutex_unlock(&wq_mu);
}

static void flush_cur(void)
{
    if (!cur_buf) return;
    if (cur_len == 0) { buf_put_free(cur_buf); cur_buf = NULL; return; }
    pthread_mutex_lock(&wq_mu);
    while (wq_count == WQ_SLOTS && !wq_stop)
        pthread_cond_wait(&wq_nonfull, &wq_mu);
    if (wq_stop) {
        pthread_mutex_unlock(&wq_mu);
        buf_put_free(cur_buf); cur_buf = NULL; cur_len = 0;
        return;
    }
    wq_buf[wq_head] = cur_buf; wq_len[wq_head] = cur_len;
    wq_head = (wq_head + 1) % WQ_SLOTS; wq_count++;
    cur_buf = NULL; cur_len = 0;
    pthread_cond_signal(&wq_nonempty);
    pthread_mutex_unlock(&wq_mu);
}

static void emit(const uint8_t *d, size_t n)
{
    if (!out || write_error) return;
    while (n) {
        if (!cur_buf) {
            pthread_mutex_lock(&wq_mu);
            while (free_n == 0 && !wq_stop)
                pthread_cond_wait(&wq_free, &wq_mu);
            if (wq_stop || free_n == 0) { pthread_mutex_unlock(&wq_mu); return; }
            cur_buf = free_buf[--free_n];
            pthread_mutex_unlock(&wq_mu);
            cur_len = 0;
        }
        size_t room = WQ_CHUNK - cur_len;
        size_t k = n < room ? n : room;
        memcpy(cur_buf + cur_len, d, k);
        cur_len += k; d += k; n -= k;
        if (cur_len == WQ_CHUNK) flush_cur();
    }
}

static void *writer_thread(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&wq_mu);
        while (wq_count == 0 && !wq_stop)
            pthread_cond_wait(&wq_nonempty, &wq_mu);
        if (wq_count == 0 && wq_stop) { pthread_mutex_unlock(&wq_mu); break; }
        uint8_t *b = wq_buf[wq_tail];
        size_t   l = wq_len[wq_tail];
        wq_tail = (wq_tail + 1) % WQ_SLOTS; wq_count--;
        pthread_cond_signal(&wq_nonfull);
        pthread_mutex_unlock(&wq_mu);
        if (!write_error && fwrite(b, 1, l, out) != l) write_error = 1;
        buf_put_free(b);
    }
    return NULL;
}

// --------------------------------------------------------------------------
// 协议
// --------------------------------------------------------------------------
static uint16_t crc16(const uint32_t w[3])
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < 12; i++) {
        uint32_t wv = w[i >> 2];
        crc ^= (uint16_t)(((wv >> ((i & 3) * 8)) & 0xFF) << 8);
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

static void build_cmd(uint8_t buf[16], unsigned seq, unsigned cid, uint32_t param)
{
    uint32_t w[3] = { ((seq & 0xFF) << 8) | (cid & 0xFF), param, 0 };
    uint32_t w0 = ((uint32_t)crc16(w) << 16) | CMD_MAGIC;
    uint32_t all[4] = { w0, w[0], w[1], w[2] };
    memcpy(buf, all, sizeof(all));
}

// --------------------------------------------------------------------------
// 上行块解析（镜像 tools/uhsif_loopback_test.py 的 Stream：
//  未对齐时先字节扫 magic(LE C6 6C)，再校验 CRC/保留位/块长；对齐后按块长步进，
//  坏头则回退到逐字节扫描。跨 URB 保留未完成块。）
// --------------------------------------------------------------------------
// ---- 采集帧走查（与 checkbits.py 同布局）----
// 帧: d[off]&0x80 为起始标志, size=((d[off+3]&7)<<8)|d[off+4],
// 标志位 d[off+3]: bit3=overflow bit4=crc_error bit5=data_error
static uint64_t rec_total, ev_crc, ev_ovf, ev_derr;
// per-packet counts (flag set on that packet's own header): the sticky flag
// makes ev_* count only EPISODES, so ovfPkts is what quantifies actual loss.
static uint64_t pkts_crc, pkts_ovf, pkts_derr;
static unsigned st_crc, st_ovf, st_derr;   // 粘滞标志的上一状态
static uint8_t  fbuf[3000];
static size_t   flen;
static int      faligned;

static void stats_push(const uint8_t *d, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (!faligned) {
            // 非数据帧是 4 字节状态帧；必须整体跳过，否则会把状态帧内部的
            // 时间戳高位（bit7 可能为 1）误当成数据帧头，锁到假帧上并把
            // 任意字节当 flags -> 凭空多报 crc/ovf/derr 事件（实测：干净流
            // 上 usbcap_fast 报 2/2/2，而 checkbits/patcheck 均为 0）。
            uint8_t c = d[i];
            if (c & 0x80) { fbuf[0] = c; flen = 1; faligned = 1; i++; }
            else { i += 4; }
            continue;
        }
        size_t need = 7;
        while (flen < need && i < n) fbuf[flen++] = d[i++];
        if (flen < need) return;
        size_t size = ((fbuf[3] & 7) << 8) | fbuf[4];
        if (size < 7 || size > 2048) { faligned = 0; flen = 0; continue; }
        while (flen < size && i < n) fbuf[flen++] = d[i++];
        if (flen < size) return;
        rec_total++;
        unsigned c = (fbuf[3] >> 4) & 1, o = (fbuf[3] >> 3) & 1, e = (fbuf[3] >> 5) & 1;
        if (c && !st_crc) ev_crc++;
        if (o && !st_ovf) ev_ovf++;
        if (e && !st_derr) ev_derr++;
        if (c) pkts_crc++;
        if (o) pkts_ovf++;
        if (e) pkts_derr++;
        st_crc = c; st_ovf = o; st_derr = e;
        faligned = 0; flen = 0;
    }
}

static uint8_t pbuf[2 * URB_SIZE_MAX + 64];
static size_t plen_buf;
static int aligned;

static void parse_push(const uint8_t *data, size_t n)
{
    memcpy(pbuf + plen_buf, data, n);
    plen_buf += n;
    size_t off = 0;
    for (;;) {
        if (!aligned) {
            size_t i;
            for (i = off; i + 1 < plen_buf; i++)
                if (pbuf[i] == 0xC6 && pbuf[i + 1] == 0x6C) break;
            if (i + 1 >= plen_buf) { off = (plen_buf > 0) ? plen_buf - 1 : 0; break; }
            off = i;
            if (plen_buf - off < 16) break;          // 头部未齐，保留候选
        } else if (plen_buf - off < 16) {
            break;
        }
        uint32_t w0, w1, w2, w3;
        memcpy(&w0, pbuf + off, 4); memcpy(&w1, pbuf + off + 4, 4);
        memcpy(&w2, pbuf + off + 8, 4); memcpy(&w3, pbuf + off + 12, 4);
        unsigned plen = (w3 >> 12) & 0xFFF;
        unsigned seq = (w3 >> 24) & 0xFF;
        uint32_t hdr[3] = { w1, w2, w3 };
        int ok = ((w0 & 0xFFFF) == BLK_MAGIC) && ((w0 >> 16) == crc16(hdr)) &&
                 ((w1 & 0xFFFFF000u) == 0) && (plen == 0 || (plen >= 1 && plen <= 4092));
        if (!ok) { off += 1; hdr_errors++; aligned = 0; continue; }
        aligned = 1;
        size_t total = 16 + 4 * (size_t)plen;
        if (plen_buf - off < total) break;
        if (last_seq >= 0 && (int)seq != ((last_seq + 1) & 0xFF)) seq_jumps++;
        last_seq = (int)seq;
        if (plen == 0) {
            acks++;
        } else {
            blocks++;
            bytes_payload += 4 * (size_t)plen;
            stats_push(pbuf + off + 16, 4 * (size_t)plen);   // 帧走查: 标志事件统计
            emit(pbuf + off + 16, 4 * (size_t)plen);
        }
        off += total;
    }
    plen_buf -= off;
    if (off) memmove(pbuf, pbuf + off, plen_buf);
}

static double now_s(void);                 // defined below
static double last_xfer_t;                 // last IN completion (monotonic s)
static double max_gap_ms;                  // worst inter-completion gap
static unsigned long gaps_gt20, gaps_gt50, xfer_count, xfer_short;
static uint64_t xfer_bytes;

static void LIBUSB_CALL on_xfer(struct libusb_transfer *tr)
{
    // 关键: 只要是"设备侧已完成/被取消以外的任何终态"，libusb 都会把已收到的
    // 字节放在 actual_length 里（超时/overflow 亦然）。只处理 COMPLETED 会把这批
    // 已收到数据静默丢掉；同时**必须重新提交**，否则一个超时就让在途 URB 减员，
    // 泄放能力逐步下降并触发设备侧回压（表现为 overflow 事件 + 丢数据）。
    if (tr->status == LIBUSB_TRANSFER_NO_DEVICE) { stopping = 1; return; }
    if (tr->status == LIBUSB_TRANSFER_CANCELLED) return;
    // Host-side servicing-cadence probe: the interval between consecutive IN
    // completions is how long the event loop went unserved.  The device pool is
    // 2.25 MiB ≈ 49 ms at 46 MB/s, so any gap approaching that backpressures the
    // capture FIFO.  This tells host stalls apart from device-side drain limits.
    {
        double tn = now_s();
        if (last_xfer_t > 0.0) {
            double g = (tn - last_xfer_t) * 1000.0;
            if (g > max_gap_ms) max_gap_ms = g;
            if (g > 20.0) gaps_gt20++;
            if (g > 50.0) gaps_gt50++;
        }
        last_xfer_t = tn;
        xfer_count++;
        xfer_bytes += tr->actual_length;
        if ((unsigned)tr->actual_length < urb_size) xfer_short++;
    }
    if (tr->actual_length)
        parse_push(tr->buffer, tr->actual_length);
    if (!stopping) {
        if (libusb_submit_transfer(tr) != 0) { fprintf(stderr, "resubmit failed\n"); stopping = 1; }
    }
}

// --------------------------------------------------------------------------
static double now_s(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int send_cmd(unsigned seq, unsigned cid, uint32_t param)
{
    uint8_t buf[16]; int transferred = 0;
    build_cmd(buf, seq, cid, param);
    int rc = libusb_bulk_transfer(dev, EP_OUT, buf, sizeof(buf), &transferred, 200);
    if (rc != 0) fprintf(stderr, "cmd 0x%02x failed: %s\n", cid, libusb_error_name(rc));
    return rc == 0 && transferred == 16;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <seconds> <out.bin> [auto|ls|fs|hs] [--urbs N] [--urb-size B]\n", argv[0]);
        return 2;
    }
    double secs = atof(argv[1]);
    const char *outpath = argv[2];
    unsigned speed = 3;                       // auto
    int null_out = 0;                         // --null: 只解析不落盘（隔离磁盘 I/O）
    urbs = 32; urb_size = 128 * 1024;
    int no_write = 0; (void)no_write;
    int test_mode = 0;                        // --test: FPGA counter full-speed (drain ceiling)
    unsigned blk_dwords = 4092;               // 0x20 SET_UPLOAD_PARAMS (16 KiB blocks,
                                              // same as the extcap plugin; the FPGA
                                              // default 1024 throttles the drain to
                                              // ~95 MB/s and URBs complete at 4 KiB)
    unsigned timeout_ms = 0;                  // 0 = 无限（默认）；>0 用于对照实验
    unsigned stall_ms = 0;                    // --stall-ms: 注入一次主机停顿，测弹性上限
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--urbs") && i + 1 < argc) urbs = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--urb-size") && i + 1 < argc) urb_size = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) timeout_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--stall-ms") && i + 1 < argc) stall_ms = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--test")) test_mode = 1;
        else if (!strcmp(argv[i], "--blk-dwords") && i + 1 < argc) blk_dwords = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--null") || !strcmp(argv[i], "--no-write")) { null_out = 1; no_write = 1; }
        else if (!strcmp(argv[i], "ls")) speed = 0;
        else if (!strcmp(argv[i], "fs")) speed = 1;
        else if (!strcmp(argv[i], "hs")) speed = 2;
        else if (!strcmp(argv[i], "auto")) speed = 3;
    }
    if (urbs < 1 || urbs > URBS_MAX) urbs = 8;
    if (urb_size < 4096 || urb_size > URB_SIZE_MAX) urb_size = 256 * 1024;

    if (libusb_init(&ctx) != 0) { fprintf(stderr, "libusb_init failed\n"); return 1; }
    dev = libusb_open_device_with_vid_pid(ctx, VID, PID);
    if (!dev) { fprintf(stderr, "device %04x:%04x not found\n", VID, PID); return 1; }
    libusb_set_auto_detach_kernel_driver(dev, 1);
    if (libusb_claim_interface(dev, 0) != 0) { fprintf(stderr, "claim interface failed\n"); return 1; }

    out = null_out ? NULL : fopen(outpath, "wb");
    if (!out && !null_out) { perror("fopen"); return 1; }
    if (out) {
        static char *obuf = NULL; obuf = malloc(8u << 20);
        if (obuf) setvbuf(out, obuf, _IOFBF, 8u << 20);
        wq_init();
        if (pthread_create(&writer_tid, NULL, writer_thread, NULL) != 0) {
            fprintf(stderr, "writer thread create failed\n");
            return 1;
        }
    }

    // 初始化序列（与 rawcap.py 一致）
    send_cmd(0, CMD_ENABLE, 0);
    send_cmd(1, CMD_RESET, 1);
    send_cmd(2, CMD_SPEED, speed);
    send_cmd(3, CMD_RESET, 0);
    {   // 排空命令期间的 ACK
        double t = now_s() + 0.05;
        while (now_s() < t) { struct timeval tv = {0, 20000}; libusb_handle_events_timeout(ctx, &tv); }
    }
    bytes_before_enable = bytes_payload;
    if (blk_dwords) send_cmd(4, CMD_UPLOAD, blk_dwords);
    if (test_mode) send_cmd(5, CMD_TEST, 1); else send_cmd(5, CMD_ENABLE, 1);
    printf("capturing %.0fs (speed=%s, urbs=%u x %u B, timeout=%ums) ...\n",
           secs, speed == 0 ? "ls" : speed == 1 ? "fs" : speed == 2 ? "hs" : "auto",
           urbs, urb_size, timeout_ms);

    for (unsigned i = 0; i < urbs; i++) {
        urb_buf[i] = malloc(urb_size);
        urb_tr[i] = libusb_alloc_transfer(0);
        libusb_fill_bulk_transfer(urb_tr[i], dev, EP_IN, urb_buf[i], urb_size,
                                  on_xfer, NULL, timeout_ms);
        if (libusb_submit_transfer(urb_tr[i]) != 0) { fprintf(stderr, "submit failed\n"); return 1; }
    }

    double t_start = now_s();
    double t_end = t_start + secs;
    int stalled = 0;
    while (now_s() < t_end && !stopping) {
        // Inject one host stall at ~40% of the capture: block event handling
        // (and thus URB resubmission) for stall_ms.  This is exactly the
        // "host did not service URBs" worst case; whether the device rides it
        // out shows the true elasticity (SRAM pool + FIFOs + in-flight URBs).
        if (stall_ms && !stalled && now_s() - t_start >= 0.4 * secs) {
            fprintf(stderr, "injecting host stall %ums @%.1fs\n", stall_ms, now_s() - t_start);
            usleep(stall_ms * 1000u);
            stalled = 1;
        }
        struct timeval tv = {0, 100000};
        libusb_handle_events_timeout(ctx, &tv);
    }

    stopping = 1;
    if (test_mode) send_cmd(6, CMD_TEST, 0); else send_cmd(6, CMD_ENABLE, 0);
    {   // 尾部排空
        double t = now_s() + 0.3;
        while (now_s() < t) { struct timeval tv = {0, 50000}; libusb_handle_events_timeout(ctx, &tv); }
    }
    for (unsigned i = 0; i < urbs; i++) { libusb_cancel_transfer(urb_tr[i]); }
    { double t = now_s() + 1.0; while (now_s() < t) { struct timeval tv = {0, 50000}; libusb_handle_events_timeout(ctx, &tv); } }
    if (out) {
        flush_cur();
        pthread_mutex_lock(&wq_mu);
        wq_stop = 1;
        pthread_cond_broadcast(&wq_nonempty);
        pthread_cond_broadcast(&wq_nonfull);
        pthread_mutex_unlock(&wq_mu);
        pthread_join(writer_tid, NULL);
        for (int i = 0; i < free_n; i++) free(free_buf[i]);
        if (write_error) fprintf(stderr, "WARNING: output write error (file truncated)\n");
        fclose(out);
    }

    printf("wrote %s: %llu B (blocks=%u acks=%u hdr_err=%u seq_jumps=%u) "
           "records=%llu crcEv=%llu ovfEv=%llu derrEv=%llu "
           "crcPkts=%llu ovfPkts=%llu derrPkts=%llu "
           "xferGap max=%.1fms >20ms=%lu >50ms=%lu stallInj=%ums "
           "xferN=%lu avg=%uB short=%lu%%\n",
           outpath, (unsigned long long)bytes_payload, blocks, acks, hdr_errors, seq_jumps,
           (unsigned long long)rec_total, (unsigned long long)ev_crc,
           (unsigned long long)ev_ovf, (unsigned long long)ev_derr,
           (unsigned long long)pkts_crc, (unsigned long long)pkts_ovf,
           (unsigned long long)pkts_derr,
           max_gap_ms, gaps_gt20, gaps_gt50, stall_ms,
           xfer_count, xfer_count ? (unsigned)(xfer_bytes / xfer_count) : 0,
           xfer_count ? (100 * xfer_short / xfer_count) : 0);
    for (unsigned i = 0; i < urbs; i++) { libusb_free_transfer(urb_tr[i]); free(urb_buf[i]); }
    libusb_release_interface(dev, 0);
    libusb_close(dev);
    libusb_exit(ctx);
    return 0;
}
