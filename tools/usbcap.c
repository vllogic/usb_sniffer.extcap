// SPDX-License-Identifier: BSD-3-Clause
// usbcap.c — 高速主机抓包工具（USB Sniffer 2 上行原始流）
//
// 与 tools/rawcap.py 等价但为 C + libusb-1.0 异步实现：
//   * 同时在途 N 个批量 IN 传输（默认 8×256 KiB），不做"一次一个"的同步往返；
//   * 上行块解析在完成回调里就地完成（magic/CRC-16/块长/seq），只把 payload 落盘；
//   * 输出与 rawcap.py 相同（UHSIF 数据块的 payload 逐字节拼接），可直接用
//     checkbits.py / checkcap.py / usb_stress.py 判读。
//
// 用法:
//   ./usbcap <seconds> <out.bin> [auto|ls|fs|hs] [--urbs N] [--urb-size BYTES]
// 退出时打印: wrote <out>: <N> B (bytes before enable: X, blocks=B acks=A)
//
// 协议（见 tools/uhsif_loopback_test.py / src/cmd.c）:
//   下行命令 4 字: W0={crc16(w1,w2,w3),0xC7F3}, W1=(seq<<8)|cid, W2=param, W3=0
//   上行块 16B 头 + payload: W0={crc16(w1,w2,w3),0x6CC6}, plen=W3[23:12], seq=W3[31:24]
//     plen==0 -> ACK；plen>0 -> 数据块（payload = plen 个 32bit 字）
//   初始化序列: ENABLE0 -> RESET1 -> SPEED -> RESET0 -> ENABLE1

#include <libusb-1.0/libusb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VID 0x1209
#define PID 0x6688
#define EP_OUT 0x01
#define EP_IN 0x81

#define CMD_MAGIC 0xC7F3u
#define BLK_MAGIC 0x6CC6u
#define CMD_RESET 0x01
#define CMD_ENABLE 0x02
#define CMD_SPEED 0x03

#define URBS_MAX 32
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
            if (out) fwrite(pbuf + off + 16, 1, 4 * (size_t)plen, out);
        }
        off += total;
    }
    plen_buf -= off;
    if (off) memmove(pbuf, pbuf + off, plen_buf);
}

static void LIBUSB_CALL on_xfer(struct libusb_transfer *tr)
{
    // 关键: 只要是"设备侧已完成/被取消以外的任何终态"，libusb 都会把已收到的
    // 字节放在 actual_length 里（超时/overflow 亦然）。只处理 COMPLETED 会把这批
    // 已收到数据静默丢掉；同时**必须重新提交**，否则一个超时就让在途 URB 减员，
    // 泄放能力逐步下降并触发设备侧回压（表现为 overflow 事件 + 丢数据）。
    if (tr->status == LIBUSB_TRANSFER_NO_DEVICE) { stopping = 1; return; }
    if (tr->status == LIBUSB_TRANSFER_CANCELLED) return;
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
    urbs = 8; urb_size = 256 * 1024;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--urbs") && i + 1 < argc) urbs = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--urb-size") && i + 1 < argc) urb_size = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--null")) null_out = 1;
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
    send_cmd(4, CMD_ENABLE, 1);
    printf("capturing %.0fs (speed=%s, urbs=%u x %u B) ...\n",
           secs, speed == 0 ? "ls" : speed == 1 ? "fs" : speed == 2 ? "hs" : "auto",
           urbs, urb_size);

    for (unsigned i = 0; i < urbs; i++) {
        urb_buf[i] = malloc(urb_size);
        urb_tr[i] = libusb_alloc_transfer(0);
        libusb_fill_bulk_transfer(urb_tr[i], dev, EP_IN, urb_buf[i], urb_size,
                                  on_xfer, NULL, 500);
        if (libusb_submit_transfer(urb_tr[i]) != 0) { fprintf(stderr, "submit failed\n"); return 1; }
    }

    double t_end = now_s() + secs;
    while (now_s() < t_end && !stopping) {
        struct timeval tv = {0, 100000};
        libusb_handle_events_timeout(ctx, &tv);
    }

    stopping = 1;
    send_cmd(5, CMD_ENABLE, 0);
    {   // 尾部排空
        double t = now_s() + 0.3;
        while (now_s() < t) { struct timeval tv = {0, 50000}; libusb_handle_events_timeout(ctx, &tv); }
    }
    for (unsigned i = 0; i < urbs; i++) { libusb_cancel_transfer(urb_tr[i]); }
    { double t = now_s() + 0.2; while (now_s() < t) { struct timeval tv = {0, 50000}; libusb_handle_events_timeout(ctx, &tv); } }
    if (out) fclose(out);

    printf("wrote %s: %llu B (bytes before enable: %llu, blocks=%u acks=%u hdr_err=%u seq_jumps=%u)\n",
           outpath, (unsigned long long)bytes_payload,
           (unsigned long long)bytes_before_enable, blocks, acks, hdr_errors, seq_jumps);
    for (unsigned i = 0; i < urbs; i++) { libusb_free_transfer(urb_tr[i]); free(urb_buf[i]); }
    libusb_release_interface(dev, 0);
    libusb_close(dev);
    libusb_exit(ctx);
    return 0;
}
