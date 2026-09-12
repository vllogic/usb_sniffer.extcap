// SPDX-License-Identifier: BSD-3-Clause
// uhsif_bulk — UHSIF v2.3 bulk-downlink bring-up and calibration tool.
//
// Talks to the usb_sniffer2 device (1209:6688) over EP1 OUT/IN and exercises
// the downlink bulk block channel (see docs/uhsif_bulk_downlink_protocol_v23_draft.md):
//
//   --probe          classic command round-trip (legacy link sanity)
//   --cmd ID PARAM   send one command, wait for ACK
//   --stats IDX      read one FPGA counter via GET_STATS (0x23)
//   --send LEN       send one bulk block with a known pattern
//   --sweep          length sweep, checked via echo or stats
//   --blocks N       repeat count for --send/--sweep
//   --echo           enable echo sink and verify returned payload word-exact
//
// F1a: the tool never re-issues SET_CONFIGURATION when the device already
// reports configuration 1 (redundant SET_CONFIGURATION wedges EP1 OUT on the
// current CH32 firmware, see docs/uhsif_downlink_dev_plan.md).
//
// Build: make tools/uhsif_bulk   (or: gcc -O2 -Isrc -o uhsif_bulk tools/uhsif_bulk.c -lusb-1.0)

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libusb-1.0/libusb.h>

#include "uhsif.h"

#define VENDOR  0x1209
#define PRODUCT 0x6688
#define EP_OUT  0x01
#define EP_IN   0x81

#define CMD_BULK_SET_CFG 0x22
#define CMD_BULK_STATS   0x23
#define CMD_ID_BULK_DATA 0x30

#define BULK_MAX_WORDS 4092
#define IN_CHUNK       262144
#define IN_TIMEOUT_MS  500

typedef struct
{
  libusb_device_handle *dev;
  libusb_context *lctx;
  u8 seq;                        // command seq for legacy commands
  u8 blk_seq;                    // per-stream bulk block seq
  u8 inbuf[IN_CHUNK * 2];
  int inlen;
  u8 last_stream;
  int blocks;                    // parsed blocks since last drain
  int acks;
  int errors;
  s64 deadline_ms;               // absolute deadline for the current wait
  // echo verification
  int echo_enable;
  u8 *echo_expect;               // expected words (LE bytes), per current block
  int echo_expect_words;
  int echo_got_words;
  int echo_mismatch;
  // last parsed ACK block header (GET_STATS reply carries w2/w3)
  u32 last_ack_w2;
  u32 last_ack_w3;
  // GET_STATS 按索引匹配 (设备 IN 可能残留历史 ACK)
  int want_idx;
  int want_found;
  u32 want_val;
  // 上下行并发: 校验 TEST_MODE 上行计数流连续性
  int conc_mode;
  int conc_started;
  u32 conc_expect;
  int conc_counter_err;
  long long upl_bytes;
} ctx;

static int g_quiet = 0;

static void die(const char *msg)
{
  fprintf(stderr, "uhsif_bulk: %s\n", msg);
  exit(1);
}

static s64 now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (s64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}

static void build_cmd(u8 *pkt, u8 seq, u8 cid, u32 param)
{
  u32 w1 = ((u32)seq << 8) | cid;
  u32 w3 = 0;
  u32 w0 = ((u32)uhsif_hdr_crc16(w1, param, w3) << 16) | UHSIF_CMD_MAGIC16;

  uhsif_put_le32(pkt + 0, w0);
  uhsif_put_le32(pkt + 4, w1);
  uhsif_put_le32(pkt + 8, param);
  uhsif_put_le32(pkt + 12, w3);
}

static void build_bulk(u8 *pkt, u8 stream, u8 blk_seq, int last, int ack_req,
                       int len_words, const u8 *payload)
{
  u32 w1 = ((u32)stream << 16) | ((u32)blk_seq << 8) | CMD_ID_BULK_DATA;
  u32 w2 = (ack_req ? 2u : 0u) | (last ? 1u : 0u);
  u32 w3 = (u32)(len_words & 0xfff);
  u32 w0 = ((u32)uhsif_hdr_crc16(w1, w2, w3) << 16) | UHSIF_CMD_MAGIC16;

  uhsif_put_le32(pkt + 0, w0);
  uhsif_put_le32(pkt + 4, w1);
  uhsif_put_le32(pkt + 8, w2);
  uhsif_put_le32(pkt + 12, w3);
  if (len_words > 0)
    memcpy(pkt + 16, payload, (size_t)len_words * 4);
}

//-----------------------------------------------------------------------------
// device
//-----------------------------------------------------------------------------
static void dev_open(ctx *c)
{
  libusb_context *lctx = NULL;
  if (libusb_init(&lctx) < 0)
    die("libusb_init failed");
  c->lctx = lctx;
  c->dev = libusb_open_device_with_vid_pid(lctx, VENDOR, PRODUCT);
  if (!c->dev)
  {
    fprintf(stderr, "device %04x:%04x not found\n", VENDOR, PRODUCT);
    exit(1);
  }

  // F1a: only set the configuration when the device is not already configured.
  int cfg = -1;
  if (libusb_get_configuration(c->dev, &cfg) == 0 && cfg != 1)
  {
    if (libusb_set_configuration(c->dev, 1) < 0)
      fprintf(stderr, "warning: set_configuration(1) failed\n");
  }

  if (libusb_kernel_driver_active(c->dev, 0) == 1)
    libusb_detach_kernel_driver(c->dev, 0);
  if (libusb_claim_interface(c->dev, 0) < 0)
    die("claim_interface failed");
}

static void dev_drain(ctx *c)
{
  u8 buf[4096];
  int n;
  for (int i = 0; i < 8; i++)
  {
    int r = libusb_bulk_transfer(c->dev, EP_IN, buf, sizeof(buf), &n, 30);
    if (r < 0 || n == 0)
      break;
  }
  c->inlen = 0;
}

static void dev_drain_deep(ctx *c)
{
  u8 buf[4096];
  int idle = 0;
  while (idle < 8)
  {
    int n = 0;
    int r = libusb_bulk_transfer(c->dev, EP_IN, buf, sizeof(buf), &n, 50);
    if (r < 0 || n == 0)
      idle++;
    else
      idle = 0;
  }
  c->inlen = 0;
}

static int raw_write(ctx *c, const u8 *data, int len)
{
  int n = 0;
  int r = libusb_bulk_transfer(c->dev, EP_OUT, (u8 *)data, len, &n, 1000);
  if (r < 0)
  {
    if (!g_quiet)
      fprintf(stderr, "EP1 OUT: %s\n", libusb_error_name(r));
    return -1;
  }
  return n;
}

// Drain EP1 IN and feed the parser. Returns bytes read (0 on timeout).
static int dev_poll_in(ctx *c, int timeout_ms)
{
  int n = 0;
  if (c->inlen >= (int)sizeof(c->inbuf))
    c->inlen = 0;
  int r = libusb_bulk_transfer(c->dev, EP_IN, c->inbuf + c->inlen,
                               (int)sizeof(c->inbuf) - c->inlen, &n, timeout_ms);
  if (r < 0 || n <= 0)
    return 0;
  c->inlen += n;
  return n;
}

//-----------------------------------------------------------------------------
// uplink block parser (magic + crc16 gated, mirrors src/stream.c semantics)
//-----------------------------------------------------------------------------
static int parse_blocks(ctx *c)
{
  int consumed_total = 0;
  for (;;)
  {
    if (c->inlen < 16)
      break;
    u32 w0 = uhsif_le32(c->inbuf + 0);
    u32 w1 = uhsif_le32(c->inbuf + 4);
    u32 w2 = uhsif_le32(c->inbuf + 8);
    u32 w3 = uhsif_le32(c->inbuf + 12);
    if (!uhsif_blk_hdr_ok(w0, w1, w2, w3))
    {
      // resync byte-wise
      memmove(c->inbuf, c->inbuf + 1, (size_t)(c->inlen - 1));
      c->inlen--;
      consumed_total++;
      c->errors++;
      continue;
    }
    int plen = (int)uhsif_blk_payload_len(c->inbuf);
    int total = UHSIF_ACK_SIZE + 4 * plen;
    if (c->inlen < total)
      break;
    if (plen == 0)
    {
      c->acks++;
      c->last_ack_w2 = w2;
      c->last_ack_w3 = w3;
      if ((int)(w3 & 0xfff) == c->want_idx)
      {
        c->want_found = 1;
        c->want_val = w2;
      }
    }
    else
    {
      c->blocks++;
      if (c->conc_mode)
      {
        const u8 *p = c->inbuf + UHSIF_ACK_SIZE;
        for (int i = 0; i < plen; i++)
        {
          u32 w = uhsif_le32(p + 4 * i);
          if (!c->conc_started)
          {
            c->conc_started = 1;
          }
          else if (w != c->conc_expect)
          {
            c->conc_counter_err++;
          }
          c->conc_expect = w + 1;
          c->upl_bytes += 4;
        }
      }
      if (c->echo_enable && c->echo_expect)
      {
        const u8 *p = c->inbuf + UHSIF_ACK_SIZE;
        for (int i = 0; i < plen && c->echo_got_words < c->echo_expect_words; i++)
        {
          if (memcmp(p + 4 * i, c->echo_expect + 4 * c->echo_got_words, 4) != 0)
          {
            if (!g_quiet)
              fprintf(stderr, "echo mismatch at word %d (block len %d): got %08x exp %08x\n",
                      c->echo_got_words, plen,
                      uhsif_le32(p + 4 * i),
                      uhsif_le32(c->echo_expect + 4 * c->echo_got_words));
            c->echo_mismatch++;
          }
          c->echo_got_words++;
        }
      }
    }
    memmove(c->inbuf, c->inbuf + total, (size_t)(c->inlen - total));
    c->inlen -= total;
    consumed_total += total;
  }
  return consumed_total;
}

// Wait until predicate satisfied or deadline.
typedef int (*wait_fn)(ctx *c, void *arg);

static int wait_until(ctx *c, wait_fn fn, void *arg, int timeout_ms)
{
  s64 deadline = now_ms() + timeout_ms;
  for (;;)
  {
    if (fn(c, arg))
      return 0;
    s64 left = deadline - now_ms();
    if (left <= 0)
      return -1;
    int n = dev_poll_in(c, left > IN_TIMEOUT_MS ? IN_TIMEOUT_MS : (int)left);
    if (n > 0)
      parse_blocks(c);
  }
}

static int want_acks(ctx *c, void *arg)
{
  int want = *(int *)arg;
  return c->acks >= want;
}

static int send_cmd_wait(ctx *c, u8 cid, u32 param, int timeout_ms)
{
  u8 pkt[UHSIF_CMD_SIZE];
  int want = c->acks + 1;
  build_cmd(pkt, c->seq, cid, param);
  if (raw_write(c, pkt, sizeof(pkt)) < 0)
    return -1;
  c->seq++;
  if (wait_until(c, want_acks, &want, timeout_ms) < 0)
  {
    if (!g_quiet)
      fprintf(stderr, "command 0x%02x: no ACK in %d ms\n", cid, timeout_ms);
    return -1;
  }
  return 0;
}

// 幂等命令重试：测速停止阶段 EP1 链可能刚被取消，单条 OUT 命令可能丢失
static int cmd_retry(ctx *c, u8 cid, u32 param, int tries, int timeout_ms)
{
  for (int i = 0; i < tries; i++)
    if (send_cmd_wait(c, cid, param, timeout_ms) == 0)
      return 0;
  return -1;
}

static int get_stat(ctx *c, int idx, u32 *value)
{
  u8 pkt[UHSIF_CMD_SIZE];
  c->want_idx = idx;
  c->want_found = 0;
  c->want_val = 0;
  build_cmd(pkt, c->seq, CMD_BULK_STATS, (u32)idx);
  if (raw_write(c, pkt, sizeof(pkt)) < 0)
    return -1;
  c->seq++;
  // 设备 EP1 IN 可能残留历史 ACK: 按索引匹配读取, 忽略陈旧应答
  s64 deadline = now_ms() + 800;
  while (now_ms() < deadline && !c->want_found)
  {
    int n = dev_poll_in(c, 150);
    if (n > 0)
      parse_blocks(c);
  }
  if (!c->want_found)
  {
    if (!g_quiet)
      fprintf(stderr, "GET_STATS(%d): no matching reply\n", idx);
    return -1;
  }
  *value = c->want_val;
  return 0;
}


//-----------------------------------------------------------------------------
// Optional payload verification on a dedicated core (pthread).  The async IN
// callback only hands the completed transfer to the verifier thread; the
// verifier checks the payload word-by-word and then resubmits the transfer, so
// the rate-measuring thread never parses data (zero-copy).
//   echo mode : every echoed block carries blk_seq -> expected word =
//               (blk_seq<<20) + k
//   TEST mode : counter-fill continuity across payload words
//-----------------------------------------------------------------------------
#if !defined(_WIN32)
#include <pthread.h>
#define UHSIF_VERIFY_THREADS 1
#else
#define UHSIF_VERIFY_THREADS 0
#endif

#define VFY_QDEPTH 32

typedef struct
{
  int echo_mode;
  struct libusb_transfer *q[VFY_QDEPTH];
  int head, tail, cnt;
  volatile int stop;
  long long blocks, mism, bad_hdr, dropped;
  volatile long long words;          // 跨线程读: 下行窗口流控用
  void (*on_progress)(void *);       // 每处理完一个 transfer 回调（驱动窗口释放）
  void *on_progress_arg;
  u8 *carry; int carry_len, carry_cap;
  u8 *scratch;
  int t_started; u32 t_expect;
#if UHSIF_VERIFY_THREADS
  pthread_mutex_t mu;
  pthread_cond_t  cv;
  pthread_t       th;
#endif
} vfy_ctx;

static void vfy_process(vfy_ctx *v, const u8 *buf, int len)
{
  const u8 *p = buf;
  int n = len, off = 0, unrebased = 0;
  if (v->carry_len)
  {
    memcpy(v->scratch, v->carry, (size_t)v->carry_len);
    memcpy(v->scratch + v->carry_len, buf, (size_t)len);
    p = v->scratch;
    n = v->carry_len + len;
    unrebased = 1;
    v->carry_len = 0;
  }
  while (off + 16 <= n)
  {
    u32 w0 = uhsif_le32(p + off), w1 = uhsif_le32(p + off + 4);
    u32 w2 = uhsif_le32(p + off + 8), w3 = uhsif_le32(p + off + 12);
    if (!uhsif_blk_hdr_ok(w0, w1, w2, w3)) { v->bad_hdr++; off++; continue; }
    int plen = (int)uhsif_blk_payload_len(p + off);
    if (off + 16 + plen * 4 > n)
      break;                            // partial block -> carry
    // 上行 payload 是下行 payload 的连续计数器（echo）或 TEST 计数流，
    // 两者都按连续性校验（块头不参与）。
    for (int k = 0; k < plen; k++)
    {
      u32 w = uhsif_le32(p + off + 16 + 4 * k);
      if (!v->t_started)
        v->t_started = 1;
      else if (w != v->t_expect)
        v->mism++;
      v->t_expect = w + 1;
    }
    v->blocks++;
    v->words += plen;
    off += 16 + plen * 4;
  }
  if (off < n)
  {
    int left = n - off;
    if (left > v->carry_cap)
      left = v->carry_cap;
    memcpy(v->carry, (unrebased ? v->scratch : buf) + off, (size_t)left);
    v->carry_len = left;
  }
}

#if UHSIF_VERIFY_THREADS
static void *vfy_thread(void *arg)
{
  vfy_ctx *v = (vfy_ctx *)arg;
  for (;;)
  {
    struct libusb_transfer *tr = NULL;
    pthread_mutex_lock(&v->mu);
    while (v->cnt == 0 && !v->stop)
      pthread_cond_wait(&v->cv, &v->mu);
    if (v->cnt > 0)
    {
      tr = v->q[v->tail];
      v->tail = (v->tail + 1) % VFY_QDEPTH;
      v->cnt--;
    }
    else
    {
      pthread_mutex_unlock(&v->mu);
      break;
    }
    pthread_mutex_unlock(&v->mu);
    vfy_process(v, tr->buffer, (int)tr->actual_length);
    if (v->on_progress)
      v->on_progress(v->on_progress_arg);
    if (!v->stop)
      libusb_submit_transfer(tr);
  }
  return NULL;
}
#endif

static int vfy_start(vfy_ctx *v, int echo_mode)
{
  memset(v, 0, sizeof(*v));
  v->echo_mode = echo_mode;
  v->carry_cap = 16 + 4092 * 4 + 16;
  v->carry   = malloc((size_t)v->carry_cap);
  v->scratch = malloc((size_t)v->carry_cap + 262144);
  if (!v->carry || !v->scratch)
    return -1;
#if UHSIF_VERIFY_THREADS
  pthread_mutex_init(&v->mu, NULL);
  pthread_cond_init(&v->cv, NULL);
  if (pthread_create(&v->th, NULL, vfy_thread, v) != 0)
    return -1;
  return 0;
#else
  return -2;
#endif
}

static void vfy_stop(vfy_ctx *v)
{
#if UHSIF_VERIFY_THREADS
  if (v->th)
  {
    pthread_mutex_lock(&v->mu);
    v->stop = 1;
    pthread_cond_broadcast(&v->cv);
    pthread_mutex_unlock(&v->mu);
    pthread_join(v->th, NULL);
    pthread_mutex_destroy(&v->mu);
    pthread_cond_destroy(&v->cv);
  }
#endif
  free(v->carry);
  v->carry = NULL;
  free(v->scratch);
  v->scratch = NULL;
}

// enqueue a completed IN transfer for verification (producer side)
static int vfy_enqueue(vfy_ctx *v, struct libusb_transfer *tr)
{
#if UHSIF_VERIFY_THREADS
  pthread_mutex_lock(&v->mu);
  if (v->cnt >= VFY_QDEPTH)
  {
    v->dropped++;
    pthread_mutex_unlock(&v->mu);
    return -1;
  }
  v->q[v->head] = tr;
  v->head = (v->head + 1) % VFY_QDEPTH;
  v->cnt++;
  pthread_cond_signal(&v->cv);
  pthread_mutex_unlock(&v->mu);
  return 0;
#else
  (void)v; (void)tr;
  return -1;
#endif
}

//-----------------------------------------------------------------------------
// Async uplink rate engine (TEST_MODE counter-fill), mirrors the extcap
// plugin's proven 8x256KiB async IN pool (src/transport_libusb.c).
//-----------------------------------------------------------------------------
typedef struct
{
  volatile int stop;
  volatile int done;
  volatile long long bytes;
  volatile int errors;
  vfy_ctx *v;                    // non-NULL -> verification on a dedicated core
} rate_state;

static void LIBUSB_CALL rate_in_cb(struct libusb_transfer *tr)
{
  rate_state *rs = (rate_state *)tr->user_data;
  if (tr->status == LIBUSB_TRANSFER_COMPLETED)
  {
    rs->bytes += tr->actual_length;
  }
  else if (tr->status == LIBUSB_TRANSFER_CANCELLED)
  {
    rs->bytes += tr->actual_length;   // bytes accepted before cancel
    rs->done++;
    return;
  }
  else if (tr->status == LIBUSB_TRANSFER_TIMED_OUT)
  {
    // 空轮询（设备暂无上行数据）：良性，直接重新提交
    if (!rs->stop && libusb_submit_transfer(tr) < 0)
      rs->errors++;
    return;
  }
  else
  {
    rs->errors++;
  }
  if (rs->stop)
  {
    rs->done++;
    return;
  }
  if (rs->v)
  {
    if (vfy_enqueue(rs->v, tr) == 0)
      return;                      // verifier resubmits after checking
    rs->errors++;                  // queue full: resubmit without checking
  }
  if (libusb_submit_transfer(tr) < 0)
    rs->errors++;
}

static int flow_rate_up(ctx *c, int seconds, int depth, int xsize)
{
  if (seconds <= 0)
    seconds = 5;
  if (depth <= 0)
    depth = 8;
  if (xsize < 16384)
    xsize = 262144;

  if (send_cmd_wait(c, UHSIF_CMD_ENABLE, 0, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 1, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_SPEED, 1, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 0, 500) < 0)
    die("rate-up startup failed");
  // 4092 words = 16 KiB 块: 默认 1024 字(4KiB)块时上报受每块头开销与 USBSS TX
  // 链重装限制（实测 ~91-95 MB/s）；16KiB 块可到链路级 ~400MB/s。
  // 与 extcap 插件 capture_speed_probe 的做法一致（src/main.c:183）。
  if (send_cmd_wait(c, UHSIF_CMD_UPLOAD_PARAMS, 4092, 500) < 0)
    die("SET_UPLOAD_PARAMS failed");
  dev_drain(c);
  if (send_cmd_wait(c, UHSIF_CMD_TEST, 1, 500) < 0)
    die("TEST_MODE on failed");

  rate_state rs;
  memset(&rs, 0, sizeof(rs));
  struct libusb_transfer **trs = calloc((size_t)depth, sizeof(*trs));
  u8 **bufs = calloc((size_t)depth, sizeof(*bufs));
  if (!trs || !bufs)
    die("out of memory");
  for (int i = 0; i < depth; i++)
  {
    bufs[i] = malloc((size_t)xsize);
    trs[i] = libusb_alloc_transfer(0);
    if (!bufs[i] || !trs[i])
      die("out of memory");
    libusb_fill_bulk_transfer(trs[i], c->dev, EP_IN, bufs[i], xsize,
                              rate_in_cb, &rs, 1000);
    if (libusb_submit_transfer(trs[i]) < 0)
      die("submit_transfer failed");
  }

  s64 t0 = now_ms();
  s64 deadline = t0 + (s64)seconds * 1000;
  while (now_ms() < deadline)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  s64 dt = now_ms() - t0;

  rs.stop = 1;
  for (int i = 0; i < depth; i++)
    libusb_cancel_transfer(trs[i]);
  s64 dl = now_ms() + 1000;
  while (rs.done < depth && now_ms() < dl)
  {
    struct timeval tv = { 0, 10000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  for (int i = 0; i < depth; i++)
  {
    libusb_free_transfer(trs[i]);
    free(bufs[i]);
  }
  free(trs);
  free(bufs);

  cmd_retry(c, UHSIF_CMD_TEST, 0, 3, 5000);
  cmd_retry(c, UHSIF_CMD_UPLOAD_PARAMS, 4092, 3, 1000);   // 恢复捕获默认块长

  double mbps = (dt > 0) ? (double)rs.bytes / (double)dt * 1000.0 / 1e6 : 0.0;
  printf("rate-up %ds depth=%d xfer=%dKiB: %lld bytes / %lld ms = %.1f MB/s "
         "(errors=%d)\n", seconds, depth, xsize / 1024, (long long)rs.bytes, (long long)dt, mbps,
         rs.errors);
  return (rs.bytes > 0 && rs.errors == 0) ? 0 : 1;
}

static void fill_pattern(u8 *buf, int words, u32 base, int pattern, u32 *sum);

//-----------------------------------------------------------------------------
// Async downlink rate engine: bulk blocks streamed asynchronously on EP1 OUT.
// Each buffer is filled with repeated 16 KiB blocks (4-word header + 4092
// payload words) so the FPGA sees consecutive v2.3 bulk blocks.
//-----------------------------------------------------------------------------
typedef struct
{
  volatile int stop;
  volatile int done;
  volatile long long bytes;
  volatile int errors;
  // verify support: rewrite the buffer with a continuous counter on each submit
  int  refill;
  int  blocks_per_buf;
  int  blk_words;
  int  blk_bytes;
  long long counter;
  // downstream window flow control: hold submissions until the echo catches up
  volatile long long *echoed;         // -> vfy.words
  long long window;                   // max words in flight (not yet echoed)
  long long submitted;                // words handed to libusb
  int  words_per_buf;
  struct libusb_transfer *held[32];
  int  nheld;
} rate_out_state;

static void rate_out_fill_buf(rate_out_state *rs, u8 *buf);

static void rate_out_submit(rate_out_state *rs, struct libusb_transfer *tr)
{
  if (rs->refill)
    rate_out_fill_buf(rs, tr->buffer);
  rs->submitted += rs->words_per_buf;
  if (libusb_submit_transfer(tr) < 0)
    rs->errors++;
}

static void rate_out_hold_or_submit(rate_out_state *rs, struct libusb_transfer *tr)
{
  if (rs->echoed && rs->window > 0 &&
      (rs->submitted - *rs->echoed) >= rs->window)
  {
    if (rs->nheld < (int)ARRAY_SIZE(rs->held))
      rs->held[rs->nheld++] = tr;
    else if (libusb_submit_transfer(tr) < 0)
      rs->errors++;
    return;
  }
  rate_out_submit(rs, tr);
}

static void rate_out_release(rate_out_state *rs);

static void rate_out_release_cb(void *arg)
{
  rate_out_release((rate_out_state *)arg);
}

static void rate_out_release(rate_out_state *rs)
{
  while (rs->nheld > 0 &&
         (rs->submitted - (rs->echoed ? *rs->echoed : 0)) < rs->window)
  {
    struct libusb_transfer *tr = rs->held[--rs->nheld];
    rate_out_submit(rs, tr);
  }
}

static void rate_out_fill_buf(rate_out_state *rs, u8 *buf)
{
  long long c = rs->counter;
  for (int b = 0; b < rs->blocks_per_buf; b++)
  {
    u8 *dst = buf + (size_t)b * rs->blk_bytes;
    fill_pattern(dst + 16, rs->blk_words, (u32)(c + (long long)b * rs->blk_words), 0, NULL);
    build_bulk(dst, 0, (u8)(rs->counter + b), 0, 0, rs->blk_words, dst + 16);
  }
  rs->counter += (long long)rs->blk_words * rs->blocks_per_buf;
}

static void LIBUSB_CALL rate_out_cb(struct libusb_transfer *tr)
{
  rate_out_state *rs = (rate_out_state *)tr->user_data;
  if (tr->status == LIBUSB_TRANSFER_COMPLETED)
  {
    rs->bytes += tr->actual_length;
  }
  else if (tr->status == LIBUSB_TRANSFER_CANCELLED)
  {
    rs->bytes += tr->actual_length;   // bytes accepted before cancel
    rs->done++;
    return;
  }
  else if (tr->status == LIBUSB_TRANSFER_TIMED_OUT)
  {
    // 空轮询（设备暂无上行数据）：良性，直接重新提交
    if (!rs->stop && libusb_submit_transfer(tr) < 0)
      rs->errors++;
    return;
  }
  else
  {
    rs->errors++;
  }
  if (rs->stop)
  {
    rs->done++;
    return;
  }
  // 窗口未释放前先挂起（防止下行远超回传导致 echo FIFO 背压丢字）
  rate_out_hold_or_submit(rs, tr);
}

static int flow_rate_down(ctx *c, int seconds, int depth, int xsize, int pattern)
{
  const int blk_words = 4092;
  const int blk_bytes = 16 + blk_words * 4;   // 16384
  if (seconds <= 0)
    seconds = 5;
  if (depth <= 0)
    depth = 8;
  if (xsize < blk_bytes)
    xsize = blk_bytes * 16;                  // default 256 KiB
  int blocks_per_buf = xsize / blk_bytes;
  if (blocks_per_buf < 1)
    blocks_per_buf = 1;
  int buf_size = blocks_per_buf * blk_bytes;

  if (send_cmd_wait(c, UHSIF_CMD_ENABLE, 0, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 1, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 0, 500) < 0)
    die("rate-down startup failed");
  dev_drain(c);

  u32 words0 = 0, blocks0 = 0;
  get_stat(c, 0, &words0);
  get_stat(c, 1, &blocks0);

  // one template block (blk_seq increments per block so content differs)
  u8 *blk = malloc((size_t)blk_bytes);
  if (!blk)
    die("out of memory");
  for (int b = 0; b < blocks_per_buf; b++)
    fill_pattern(blk + 16, blk_words, 0x10000000u + (u32)b * 0x100000u,
                 pattern, NULL);

  rate_out_state rs;
  memset(&rs, 0, sizeof(rs));
  struct libusb_transfer **trs = calloc((size_t)depth, sizeof(*trs));
  u8 **bufs = calloc((size_t)depth, sizeof(*bufs));
  if (!trs || !bufs)
    die("out of memory");
  for (int i = 0; i < depth; i++)
  {
    bufs[i] = malloc((size_t)buf_size);
    trs[i] = libusb_alloc_transfer(0);
    if (!bufs[i] || !trs[i])
      die("out of memory");
    for (int b = 0; b < blocks_per_buf; b++)
    {
      u8 *dst = bufs[i] + (size_t)b * blk_bytes;
      memcpy(dst + 16, blk + 16, (size_t)blk_words * 4);
      build_bulk(dst, 0, (u8)(i * 7 + b), 0, 0, blk_words, dst + 16);
    }
    libusb_fill_bulk_transfer(trs[i], c->dev, EP_OUT, bufs[i], buf_size,
                              rate_out_cb, &rs, 1000);
    if (libusb_submit_transfer(trs[i]) < 0)
      die("submit_transfer failed");
  }

  s64 t0 = now_ms();
  s64 deadline = t0 + (s64)seconds * 1000;
  while (now_ms() < deadline)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  s64 dt = now_ms() - t0;

  rs.stop = 1;
  for (int i = 0; i < depth; i++)
    libusb_cancel_transfer(trs[i]);
  s64 dl = now_ms() + 2000;
  while (rs.done < depth && now_ms() < dl)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  for (int i = 0; i < depth; i++)
  {
    libusb_free_transfer(trs[i]);
    free(bufs[i]);
  }
  free(trs);
  free(bufs);
  free(blk);

  sleep_ms(200);                            // 等 FPGA 消费完最后几块
  u32 words1 = 0, blocks1 = 0;
  for (int tries = 0; tries < 3; tries++)
  {
    if (get_stat(c, 0, &words1) == 0 && get_stat(c, 1, &blocks1) == 0)
      break;
    sleep_ms(200);
  }
  long long exp_blocks = rs.bytes / blk_bytes;
  long long exp_words = exp_blocks * blk_words;
  long long got_words = (long long)(words1 - words0);
  long long got_blocks = (long long)(u16)(blocks1 - blocks0);  // 16-bit 回绕
  int ok = (got_words >= exp_words - (long long)depth * blk_words) &&
           (got_words <= exp_words + (long long)depth * blk_words);
  double mbps = (dt > 0) ? (double)rs.bytes / (double)dt * 1000.0 / 1e6 : 0.0;
  printf("rate-down %ds depth=%d buf=%dKiB: %lld bytes / %lld ms = %.1f MB/s "
         "(errors=%d) consumed=%lld/%lld words blocks=%lld/%lld %s\n",
         seconds, depth, buf_size / 1024, rs.bytes, (long long)dt, mbps,
         rs.errors, got_words, exp_words, got_blocks, exp_blocks,
         ok ? "PASS" : "CHECK");
  return (rs.bytes > 0 && rs.errors == 0) ? 0 : 1;
}

//-----------------------------------------------------------------------------
// Independent bidirectional rate test: async bulk downlink (line1) while the
// FPGA streams the TEST_MODE counter fill upstream (line0).  The UHSIF bus is
// half-duplex and shared, so the two rates together approximate the link cap.
//-----------------------------------------------------------------------------
static int flow_rate_bidir(ctx *c, int seconds, int depth, int xsize,
                           int pattern, int echo_mode, int verify)
{
  const int blk_words = 4092;
  const int blk_bytes = 16 + blk_words * 4;
  if (seconds <= 0)
    seconds = 5;
  if (depth <= 0)
    depth = 8;
  if (xsize < blk_bytes)
    xsize = blk_bytes * 16;
  int blocks_per_buf = xsize / blk_bytes;
  if (blocks_per_buf < 1)
    blocks_per_buf = 1;
  int buf_size = blocks_per_buf * blk_bytes;

  if (send_cmd_wait(c, UHSIF_CMD_ENABLE, 0, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 1, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 0, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_UPLOAD_PARAMS, 4092, 500) < 0)
    die("rate-concurrent startup failed");
  dev_drain(c);
  u32 words0 = 0;
  int have_stats = 0;
  for (int t = 0; t < 3; t++)
  {
    if (get_stat(c, 0, &words0) == 0)
    {
      have_stats = 1;
      break;
    }
    sleep_ms(150);
  }

  if (echo_mode)
  {
    // 回环：上行取 echo FIFO；先设 16KiB 满块阈值以降低块开销
    if (send_cmd_wait(c, CMD_BULK_SET_CFG, 1u << 20, 500) < 0)
      die("SET_BULK_CFG echo_en failed");
  }
  else if (send_cmd_wait(c, UHSIF_CMD_TEST, 1, 500) < 0)
  {
    die("TEST_MODE on failed");
  }

  rate_state rs_in;
  rate_out_state rs_out;
  memset(&rs_in, 0, sizeof(rs_in));
  memset(&rs_out, 0, sizeof(rs_out));

  vfy_ctx vfy;
  int vfy_on = 0;
  if (verify && pattern != 0)
  {
    fprintf(stderr, "verify: only the counter pattern is verifiable; disabled\n");
    verify = 0;
  }
  if (verify)
  {
    int vr = vfy_start(&vfy, echo_mode);
    if (vr == 0)
      vfy_on = 1;
    else if (vr == -2)
      fprintf(stderr, "verify: no thread support on this build; disabled\n");
    else
      fprintf(stderr, "verify: thread start failed; disabled\n");
  }
  if (vfy_on)
  {
    rs_in.v = &vfy;
    vfy.on_progress = rate_out_release_cb;
    vfy.on_progress_arg = &rs_out;
  }

  // echo 回环校验：下行 payload 用全局连续计数器，每次重新提交时重写缓冲，
  // 使回传 payload 是一个可连续性校验的已知序列
  rs_out.blocks_per_buf = blocks_per_buf;
  rs_out.blk_words      = blk_words;
  rs_out.blk_bytes      = blk_bytes;
  rs_out.counter        = 0;
  rs_out.refill         = (echo_mode && vfy_on) ? 1 : 0;

  struct libusb_transfer **tin = calloc((size_t)depth, sizeof(*tin));
  u8 **bin = calloc((size_t)depth, sizeof(*bin));
  struct libusb_transfer **tout = calloc((size_t)depth, sizeof(*tout));
  u8 **bout = calloc((size_t)depth, sizeof(*bout));
  if (!tin || !bin || !tout || !bout)
    die("out of memory");

  for (int i = 0; i < depth; i++)
  {
    bin[i] = malloc((size_t)xsize);
    tin[i] = libusb_alloc_transfer(0);
    if (!bin[i] || !tin[i])
      die("out of memory");
    libusb_fill_bulk_transfer(tin[i], c->dev, EP_IN, bin[i], xsize,
                              rate_in_cb, &rs_in, 1000);
    if (libusb_submit_transfer(tin[i]) < 0)
      die("submit IN failed");

    bout[i] = malloc((size_t)buf_size);
    tout[i] = libusb_alloc_transfer(0);
    if (!bout[i] || !tout[i])
      die("out of memory");
    if (rs_out.refill)
    {
      rate_out_fill_buf(&rs_out, bout[i]);   // 连续计数器
    }
    else
    {
      for (int b = 0; b < blocks_per_buf; b++)
      {
        u8 *dst = bout[i] + (size_t)b * blk_bytes;
        u8 seq = (u8)(i * 7 + b);
        fill_pattern(dst + 16, blk_words, (u32)seq << 20, pattern, NULL);
        build_bulk(dst, 0, seq, 0, 0, blk_words, dst + 16);
      }
    }
    libusb_fill_bulk_transfer(tout[i], c->dev, EP_OUT, bout[i], buf_size,
                              rate_out_cb, &rs_out, 1000);
    if (libusb_submit_transfer(tout[i]) < 0)
      die("submit OUT failed");
  }

  s64 t0 = now_ms();
  s64 deadline = t0 + (s64)seconds * 1000;
  while (now_ms() < deadline)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  s64 dt = now_ms() - t0;

  rs_in.stop = 1;
  rs_out.stop = 1;
  if (vfy_on)
    vfy_stop(&vfy);          // 先停校验线程（会回填/排空转移），再取消
  for (int i = 0; i < depth; i++)
  {
    libusb_cancel_transfer(tin[i]);
    libusb_cancel_transfer(tout[i]);
  }
  s64 dl = now_ms() + 2000;
  while ((rs_in.done < depth || rs_out.done < depth) && now_ms() < dl)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
  }
  for (int i = 0; i < depth; i++)
  {
    libusb_free_transfer(tin[i]);
    free(bin[i]);
    libusb_free_transfer(tout[i]);
    free(bout[i]);
  }
  free(tin);
  free(bin);
  free(tout);
  free(bout);

  if (echo_mode)
    cmd_retry(c, CMD_BULK_SET_CFG, 0, 3, 1000);
  else
    cmd_retry(c, UHSIF_CMD_TEST, 0, 3, 5000);
  cmd_retry(c, UHSIF_CMD_UPLOAD_PARAMS, 4092, 3, 1000);
  sleep_ms(200);
  u32 words1 = 0;
  for (int tries = 0; tries < 3; tries++)
  {
    if (get_stat(c, 0, &words1) == 0)
      break;
    sleep_ms(200);
  }

  double down_mbps = (dt > 0) ? (double)rs_out.bytes / (double)dt * 1000.0 / 1e6 : 0;
  double up_mbps = (dt > 0) ? (double)rs_in.bytes / (double)dt * 1000.0 / 1e6 : 0;
  long long exp_words = (rs_out.bytes / blk_bytes) * blk_words;
  long long got_words = (long long)(u32)(words1 - words0);
  int vfy_ok = (!vfy_on) || (vfy.mism == 0 && vfy.bad_hdr == 0 && vfy.dropped == 0);
  int ok = (rs_in.bytes > 0) && (rs_out.bytes > 0) &&
           (rs_in.errors == 0) && (rs_out.errors == 0) && vfy_ok;
  printf("%s %ds depth=%d buf=%dKiB: down=%.1f MB/s (%lld B) "
         "up=%.1f MB/s (%lld B) total=%.1f MB/s errors=%d/%d consumed=%s %s\n",
         echo_mode ? "rate-loop" : "rate-concurrent", seconds, depth,
         buf_size / 1024, down_mbps, rs_out.bytes, up_mbps,
         rs_in.bytes, down_mbps + up_mbps, rs_in.errors, rs_out.errors,
         have_stats ? "" : "n/a", ok ? "PASS" : "CHECK");
  if (have_stats && exp_words > 0)
    printf("  downlink consumed=%lld/%lld words\n", got_words, exp_words);
  if (vfy_on)
    printf("  verify(%s): blocks=%lld words=%lld mism=%lld bad_hdr=%lld dropped=%lld %s\n",
           echo_mode ? "echo" : "counter", vfy.blocks, vfy.words, vfy.mism,
           vfy.bad_hdr, vfy.dropped, vfy_ok ? "OK" : "FAIL");
  return ok ? 0 : 1;
}


//-----------------------------------------------------------------------------
// Per-length loopback verification run (used by --loop-sweep).
// One length per call: echo enabled, downlink blocks of `words` payload words,
// UPLOAD_PARAMS = words so every block is echoed back immediately; the run
// lasts `ms`, then in-flight OUT transfers are drained (no mid-block cancel),
// the echoed stream is fully received, and only then the next length starts.
//-----------------------------------------------------------------------------
typedef struct
{
  int       words, bytes;
  double    down_mbps, up_mbps;
  long long vfy_blocks, vfy_words, vfy_mism, vfy_hdr, vfy_drop;
  long long expected_words;
  int       errors_in, errors_out, ran;
} loop_stat;

static int loop_once(ctx *c, int words, int ms, int depth, int window,
                     int verify, loop_stat *st)
{
  const int blk_words = words;
  const int blk_bytes = 16 + blk_words * 4;
  memset(st, 0, sizeof(*st));
  st->words = words;
  st->bytes = blk_words * 4;
  st->ran = 0;
  if (ms <= 0)
    ms = 200;
  if (depth <= 0)
    depth = 8;

  // 一个批量块 = 一次主机写入(≤16KB) = 一次 H417 传输：让 AE# 在块尾收尾，
  // 避免"H417 传输内含多块、块尾靠计数早停(中途撤 RD#)"造成的丢字。
  // 实测 16B..16KB 全长度逐字校验零错误（含块长为 1024 整数倍的长度）。
  int blocks_per_buf = 1;
  int buf_size = blk_bytes;
  (void)buf_size;

  if (send_cmd_wait(c, UHSIF_CMD_ENABLE, 0, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 1, 500) < 0 ||
      send_cmd_wait(c, UHSIF_CMD_RESET, 0, 500) < 0)
    return -1;
  // 上行满块阈值 3072：必须小于 echo 暂停阈值(4084)，否则 FIFO 卡在
  // 4085..4091 之间既不够满块触发、也不放行 RX，只能靠 10ms 超时聚合。
  cmd_retry(c, UHSIF_CMD_UPLOAD_PARAMS, 3072, 3, 1000);
  if (send_cmd_wait(c, CMD_BULK_SET_CFG, 1u << 20, 500) < 0)
    return -1;
  sleep_ms(20);
  dev_drain_deep(c);

  // 起始消费字数（用于把"期望回传量"锚定到 FPGA 实际消费，而非主机提交量）
  u32 w0 = 0;
  if (get_stat(c, 0, &w0) != 0)
    w0 = 0;
  volatile long long consumed_v = 0;   // 轮询 GET_STATS 得到的已消费字数

  vfy_ctx vfy;
  int vfy_on = 0;
  if (verify)
  {
    int vr = vfy_start(&vfy, 1);
    if (vr == 0)
      vfy_on = 1;
  }

  rate_state rs_in;
  rate_out_state rs_out;
  memset(&rs_in, 0, sizeof(rs_in));
  memset(&rs_out, 0, sizeof(rs_out));
  rs_out.blocks_per_buf = blocks_per_buf;
  rs_out.blk_words      = blk_words;
  rs_out.blk_bytes      = blk_bytes;
  rs_out.counter        = 0;
  rs_out.refill         = vfy_on ? 1 : 0;
  rs_out.words_per_buf  = blocks_per_buf * blk_words;
  rs_out.submitted      = 0;
  rs_out.nheld          = 0;
  rs_out.echoed         = (verify && window > 0) ? &consumed_v : NULL;
  // 窗口必须小于 echo FIFO 深度(4096 words)，否则 FIFO 会填满并使核心丢字
  // 窗口默认关闭：核心 RX 缺少 sink 反压（内部 skid 满即丢字）时，只能靠
  // 工具窗口化限速，但会破坏流水线、大块也变慢；因此默认与 --rate-loop 一致
  // 全速提交，由 RTL 后续修复反压。可用 --loop-window 显式限速调试。
  rs_out.window         = (verify && window > 0) ? window : 0;
  s64 last_poll = 0;
  if (vfy_on)
  {
    rs_in.v = &vfy;
    vfy.on_progress = rate_out_release_cb;
    vfy.on_progress_arg = &rs_out;
  }

  struct libusb_transfer **tin = calloc((size_t)depth, sizeof(*tin));
  u8 **bin = calloc((size_t)depth, sizeof(*bin));
  struct libusb_transfer **tout = calloc((size_t)depth, sizeof(*tout));
  u8 **bout = calloc((size_t)depth, sizeof(*bout));
  if (!tin || !bin || !tout || !bout)
    die("out of memory");

  for (int i = 0; i < depth; i++)
  {
    bin[i] = malloc(262144);
    tin[i] = libusb_alloc_transfer(0);
    if (!bin[i] || !tin[i])
      die("out of memory");
    libusb_fill_bulk_transfer(tin[i], c->dev, EP_IN, bin[i], 262144,
                              rate_in_cb, &rs_in, 1000);
    if (libusb_submit_transfer(tin[i]) < 0)
      die("submit IN failed");

    bout[i] = malloc((size_t)buf_size);
    tout[i] = libusb_alloc_transfer(0);
    if (!bout[i] || !tout[i])
      die("out of memory");
    if (!rs_out.refill)
    {
      for (int b = 0; b < blocks_per_buf; b++)
      {
        u8 *dst = bout[i] + (size_t)b * blk_bytes;
        fill_pattern(dst + 16, blk_words, (u32)((i * 7 + b) << 20), 0, NULL);
        build_bulk(dst, 0, (u8)(i * 7 + b), 0, 0, blk_words, dst + 16);
      }
    }
    libusb_fill_bulk_transfer(tout[i], c->dev, EP_OUT, bout[i], buf_size,
                              rate_out_cb, &rs_out, 1000);
    rate_out_hold_or_submit(&rs_out, tout[i]);
  }

  s64 t0 = now_ms();
  s64 deadline = t0 + (s64)ms;
  while (now_ms() < deadline)
  {
    struct timeval tv = { 0, 200 };           // 200us 事件轮询
    libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
    if (rs_out.window > 0 && (now_ms() - last_poll) >= 1)
    {
      u32 w = 0;
      if (get_stat(c, 0, &w) == 0)
        consumed_v = (long long)(u32)(w - w0);
      last_poll = now_ms();
    }
    rate_out_release(&rs_out);
  }
  s64 dt = now_ms() - t0;
  st->ran = 1;
  if (dt <= 0)
    dt = 1;

  // 停止新提交，等在飞 OUT 全部完成（不中途取消 → 不留半块）
  rs_out.stop = 1;
  {
    s64 dl = now_ms() + 3000;
    while ((rs_out.done + rs_out.nheld) < depth && now_ms() < dl)
    {
      struct timeval tv = { 0, 5000 };
      libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
    }
  }
  // 期望回传量 = FPGA 实际消费的 payload 字数（提交未必全部被消费）
  {
    u32 w1 = 0;
    if (get_stat(c, 0, &w1) == 0)
      st->expected_words = (long long)(u32)(w1 - w0);
    else
      st->expected_words = rs_out.submitted;
  }

  // 等回环数据全部回传并校验完（最后的短块可能由 10ms 聚合触发，给足余量）
  if (vfy_on)
  {
    s64 dl = now_ms() + 10000;
    int stuck = 0;
    long long last = -1;
    while (vfy.words < st->expected_words && now_ms() < dl)
    {
      struct timeval tv = { 0, 5000 };
      libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
      if (vfy.words == last)
        stuck++;
      else
      {
        stuck = 0;
        last = vfy.words;
      }
      (void)stuck;
    }
  }

  rs_in.stop = 1;
  if (vfy_on)
    vfy_stop(&vfy);
  for (int i = 0; i < depth; i++)
  {
    libusb_cancel_transfer(tin[i]);
    libusb_cancel_transfer(tout[i]);
  }
  {
    s64 dl = now_ms() + 1000;
    while (now_ms() < dl)
    {
      struct timeval tv = { 0, 5000 };
      libusb_handle_events_timeout_completed(c->lctx, &tv, NULL);
    }
  }
  for (int i = 0; i < depth; i++)
  {
    libusb_free_transfer(tin[i]);
    free(bin[i]);
    libusb_free_transfer(tout[i]);
    free(bout[i]);
  }
  free(tin);
  free(bin);
  free(tout);
  free(bout);

  cmd_retry(c, CMD_BULK_SET_CFG, 0, 3, 1000);          // echo off（同时清 FIFO）
  cmd_retry(c, UHSIF_CMD_UPLOAD_PARAMS, 4092, 3, 1000);
  sleep_ms(50);
  dev_drain_deep(c);                                  // 清掉本长度残留，长度间解耦

  st->down_mbps = (double)rs_out.bytes / (double)dt * 1000.0 / 1e6;
  st->up_mbps   = (double)rs_in.bytes / (double)dt * 1000.0 / 1e6;
  st->errors_in = rs_in.errors;
  st->errors_out = rs_out.errors;
  if (vfy_on)
  {
    st->vfy_blocks = vfy.blocks;
    st->vfy_words  = vfy.words;
    st->vfy_mism   = vfy.mism;
    st->vfy_hdr    = vfy.bad_hdr;
    st->vfy_drop   = vfy.dropped;
  }
  int ok = (rs_out.bytes > 0) && (rs_in.bytes > 0) &&
           (rs_in.errors == 0) && (rs_out.errors == 0);
  if (vfy_on)
    ok = ok && (vfy.mism == 0) && (vfy.bad_hdr == 0) && (vfy.dropped == 0) &&
         (vfy.words == st->expected_words);
  st->expected_words = ok ? st->expected_words : st->expected_words;   // 保留
  return ok ? 0 : 1;
}

// "4-1024,1028,1032" -> bytes list; step 4 for ranges; 4-byte aligned only
static int parse_len_spec(const char *spec, int *out, int cap, int step)
{
  int n = 0;
  const char *p = spec;
  while (*p && n < cap)
  {
    char *end = NULL;
    long a = strtol(p, &end, 0);
    if (end == p)
      break;
    long b = a;
    p = end;
    if (*p == '-')
    {
      p++;
      b = strtol(p, &end, 0);
      if (end == p)
        break;
      p = end;
    }
    if (step < 4)
      step = 4;
    for (long v = a; v <= b && n < cap; v += step)
      out[n++] = (int)v;
    while (*p == ',' || *p == ' ')
      p++;
  }
  return n;
}

static int flow_loop_sweep(ctx *c, const int *lens, int nlens, int ms,
                           int depth, int verify, int pattern, int window)
{
  if (pattern != 0)
  {
    fprintf(stderr, "loop-sweep: only the counter pattern is verifiable; "
                    "forcing counter\n");
  }
  int fails = 0;
  printf("loop-sweep: %d lengths, %d ms each (bytes must be 4-aligned)\n",
         nlens, ms);
  printf("%8s %6s %10s %10s %10s %8s %6s %-13s %-8s %-6s %s\n",
         "bytes", "words", "downMB/s", "upMB/s", "vfy_words", "mism", "blocks",
         "expected", "dropped", "badhdr", "result");
  for (int i = 0; i < nlens; i++)
  {
    int bytes = lens[i];
    if (bytes < 16 || bytes > 16368 || (bytes & 3))
    {
      printf("%8d %6s  -- skip: need 16..16368, 4-byte aligned (min 16B)\n",
             bytes, "-");
      fails++;
      continue;
    }
    loop_stat st;
    int rc = loop_once(c, bytes / 4, ms, depth, window, verify, &st);
    printf("%8d %6d %10.1f %10.1f %10lld %8lld %6lld exp=%-9lld drp=%-6lld hdr=%-4lld io=%d/%d %s\n",
           bytes, st.words, st.down_mbps, st.up_mbps, st.vfy_words, st.vfy_mism,
           st.vfy_blocks, st.expected_words, st.vfy_drop, st.vfy_hdr,
           st.errors_in, st.errors_out, rc == 0 ? "PASS" : "FAIL");
    if (rc != 0)
      fails++;
  }
  printf("loop-sweep: %d/%d pass\n", nlens - fails, nlens);
  return fails ? 1 : 0;
}

//-----------------------------------------------------------------------------
// patterns
//-----------------------------------------------------------------------------
static u32 prng_state = 0x12345678;

static u32 prng_next(void)
{
  u32 x = prng_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  prng_state = x;
  return x;
}

static void fill_pattern(u8 *buf, int words, u32 base, int pattern, u32 *sum)
{
  u32 acc = 0;
  for (int i = 0; i < words; i++)
  {
    u32 v = (pattern == 1) ? prng_next() : base + (u32)i;
    uhsif_put_le32(buf + 4 * i, v);
    acc += v;
  }
  if (sum)
    *sum = acc;
}

//-----------------------------------------------------------------------------
// test flows
//-----------------------------------------------------------------------------
static int flow_probe(ctx *c)
{
  if (send_cmd_wait(c, UHSIF_CMD_ENABLE, 0, 500) < 0) return -1;
  if (send_cmd_wait(c, UHSIF_CMD_RESET, 1, 500) < 0) return -1;
  if (send_cmd_wait(c, UHSIF_CMD_SPEED, 1, 500) < 0) return -1;
  if (send_cmd_wait(c, UHSIF_CMD_RESET, 0, 500) < 0) return -1;
  printf("probe: 4/4 commands acknowledged (seq=%u)\n", c->seq);
  return 0;
}

static int flow_send(ctx *c, int len_words, int pattern, int ack_req, int gap_us,
                     u32 *out_sum)
{
  if (len_words < 1 || len_words > BULK_MAX_WORDS)
  {
    fprintf(stderr, "len %d out of range 1..%d\n", len_words, BULK_MAX_WORDS);
    return -1;
  }
  u8 *pkt = malloc(16 + (size_t)len_words * 4);
  if (!pkt)
    die("out of memory");
  u32 psum = 0;
  fill_pattern(pkt + 16, len_words, 0x1000u * (u32)c->blk_seq, pattern, &psum);
  if (out_sum)
    *out_sum = psum;
  build_bulk(pkt, 0, c->blk_seq, 0, ack_req, len_words, pkt + 16);

  if (c->echo_enable)
  {
    c->echo_expect = pkt + 16;
    c->echo_expect_words = len_words;
    c->echo_got_words = 0;
    c->echo_mismatch = 0;
  }

  int acks0 = c->acks;
  int blocks0 = c->blocks;
  int r = raw_write(c, pkt, 16 + len_words * 4);
  if (r < 0)
  {
    free(pkt);
    return -1;
  }
  c->blk_seq++;
  if (gap_us > 0)
    sleep_ms(gap_us / 1000);

  if (c->echo_enable)
  {
    s64 deadline = now_ms() + 4000;
    while (c->echo_got_words < c->echo_expect_words)
    {
      if (now_ms() > deadline)
      {
        fprintf(stderr, "echo: got %d/%d words, timeout\n",
                c->echo_got_words, c->echo_expect_words);
        c->echo_expect = NULL;
        free(pkt);
        return -1;
      }
      int n = dev_poll_in(c, 200);
      if (n > 0)
        parse_blocks(c);
    }
    c->echo_expect = NULL;
    int em = c->echo_mismatch;
    free(pkt);            // 校验完成后再释放（echo_expect 指向 pkt+16）
    return em ? -1 : 0;
  }

  if (ack_req)
  {
    int want = acks0 + 1;
    if (wait_until(c, want_acks, &want, 1000) < 0)
    {
      fprintf(stderr, "len %d: no bulk ACK\n", len_words);
      free(pkt);
      return -1;
    }
  }
  (void)blocks0;
  free(pkt);
  return 0;
}

static int flow_sweep(ctx *c, const int *lens, int nlen, int pattern,
                      int ack_req, int echo)
{
  int fails = 0;
  for (int i = 0; i < nlen; i++)
  {
    int len = lens[i];
    if (echo)
    {
      if (flow_send(c, len, pattern, ack_req, 0, NULL) != 0)
      {
        printf("len %4d  FAIL\n", len);
        fails++;
        continue;
      }
    }
    else
    {
      u32 words0 = 0, blocks0 = 0, sum0 = 0, esum = 0;
      get_stat(c, 0, &words0);
      get_stat(c, 1, &blocks0);
      get_stat(c, 5, &sum0);
      if (flow_send(c, len, pattern, ack_req, 0, &esum) != 0)
      {
        printf("len %4d  SEND-FAIL\n", len);
        fails++;
        continue;
      }
      sleep_ms(5);
      u32 words1 = 0, blocks1 = 0, sum1 = 0, hdrcyc = 0;
      get_stat(c, 0, &words1);
      get_stat(c, 1, &blocks1);
      get_stat(c, 5, &sum1);
      get_stat(c, 6, &hdrcyc);
      int dwords = (int)(words1 - words0);
      int dblocks = (int)(blocks1 - blocks0);
      u32 dsum = sum1 - sum0;
      int ok = (dwords == len) && (dblocks == 1) && (dsum == esum);
      printf("len %4d  sent=%4d consumed=%4d blocks=%d sum=%s hdr=%u  %s\n",
             len, len, dwords, dblocks, (dsum == esum) ? "ok" : "BAD",
             hdrcyc, ok ? "PASS" : "CHECK");
      if (!ok)
        fails++;
    }
  }
  return fails;
}

//-----------------------------------------------------------------------------
// main
//-----------------------------------------------------------------------------
static int parse_int_list(const char *s, int *out, int cap)
{
  int n = 0;
  while (*s && n < cap)
  {
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s)
      break;
    out[n++] = (int)v;
    s = end;
    while (*s == ',' || *s == ' ')
      s++;
  }
  return n;
}

static void usage(const char *argv0)
{
  fprintf(stderr,
    "usage: %s [options] <flow>\n"
    "flows:\n"
    "  --probe                legacy command round-trip check\n"
    "  --cmd <id> [--param <v>]  send one command and wait ACK\n"
    "  --ver                  read block header VER (bulk support gate)\n"
    "  --stats <idx>          read FPGA counter via GET_STATS\n"
    "  --send <len>           send one bulk block (payload words)\n"
    "  --stream               send --blocks x --send len, verify + throughput\n"
    "  --concurrent           TEST_MODE uplink + bulk downlink, verify both\n"
    "  --rate-up              async TEST_MODE uplink rate test (default 5s)\n"
    "  --rate-down            async bulk-downlink rate test (default 5s)\n"
    "  --rate-concurrent      async downlink + TEST_MODE uplink rate test\n"
    "  --rate-loop            async true loopback (echo) rate test\n"
    "  --verify               verify payload on a dedicated core (rate-loop/-concurrent)\n"
    "  --loop-sweep           per-length echo verify sweep (see --loop-lens/-ms)\n"
    "  --loop-lens <spec>     bytes: N, A-B (step 4), comma list, e.g. 256,1024,4096,16368\n"
    "  --loop-ms <ms>         per-length run time in ms (default 200)\n"
    "  --loop-step <bytes>    step for A-B ranges (default 4)\n"
    "  --loop-desc            sort sweep lengths descending (large -> small)\n"
    "  --loop-window <words>  throttle downlink in-flight words (<4096 for echo)\n"
    "  --diag <len>           send one block then dump rx stats\n"
    "  --sweep                length sweep (default boundary list)\n"
    "options:\n"
    "  --blocks <n>           blocks per length in sweep (default 1)\n"
    "  --len-list <a,b,...>   custom sweep lengths\n"
    "  --pattern counter|prbs\n"
    "  --echo                 enable echo sink and verify payload\n"
    "  --ack                  request per-block ACK\n"
    "  --ack-en               enable SET_BULK_CFG global ACK\n"
    "  --push-lead <0-3>      SET_BULK_CFG payload push lead cycles\n"
    "  --stop-lead <0-15>     SET_BULK_CFG counted-read early stop cycles\n"
    "  --rd-cap <0-15>        SET_BULK_CFG absolute read-cycle cap (0=off)\n"
    "  --gap-us <n>           inter-block gap\n"
    "  --recover              soft-reset the device on exit\n"
    "  --quiet\n", argv0);
}

int main(int argc, char **argv)
{
  static const int default_lens[] = {
    1, 2, 3, 4, 5, 15, 16, 17, 255, 256, 257, 511, 512, 513,
    1023, 1024, 1025, 1535, 1536, 1537, 4091, 4092
  };
  const char *flow = NULL;
  int arg_id = 0, arg_param = 0, arg_len = 64, arg_stats = -1;
  int blocks_per = 1, pattern = 0, echo = 0, ack_req = 0, ack_en = 0, gap_us = 0;
  int push_lead = 0, stop_lead = 0, rd_cap = 0;
  int arg_seconds = 5, arg_depth = 8, arg_xfer = 262144, verify = 0;
  int loop_ms = 200, loop_desc = 0, loop_window = 0, loop_step = 4;
  const char *loop_lens = NULL;
  int recover = 0;
  int lens[64];
  int nlen = 0;

  static const struct option opts[] = {
    { "probe",    no_argument,       NULL, 'p' },
    { "cmd",      required_argument, NULL, 'c' },
    { "param",    required_argument, NULL, 'C' },
    { "ver",      no_argument,       NULL, 'V' },
    { "stats",    required_argument, NULL, 's' },
    { "send",     required_argument, NULL, 'S' },
    { "stream",   no_argument,       NULL, 'M' },
    { "concurrent",no_argument,      NULL, 'U' },
    { "rate-up",  no_argument,       NULL, 'Y' },
    { "rate-down",no_argument,       NULL, 'W' },
    { "rate-concurrent",no_argument, NULL, 'X' },
    { "rate-loop",no_argument, NULL, 'Q' },
    { "verify",    no_argument, NULL, '9' },
    { "loop-sweep",no_argument, NULL, '8' },
    { "loop-lens", required_argument, NULL, '7' },
    { "loop-ms",   required_argument, NULL, '6' },
    { "loop-desc", no_argument, NULL, '5' },
    { "loop-window", required_argument, NULL, '4' },
    { "loop-step", required_argument, NULL, '3' },
    { "seconds",  required_argument, NULL, 'Z' },
    { "depth",    required_argument, NULL, '1' },
    { "xfer-size",required_argument, NULL, '2' },
    { "diag",     required_argument, NULL, 'D' },
    { "sweep",    no_argument,       NULL, 'w' },
    { "blocks",   required_argument, NULL, 'b' },
    { "len-list", required_argument, NULL, 'l' },
    { "pattern",  required_argument, NULL, 'P' },
    { "echo",     no_argument,       NULL, 'e' },
    { "ack",      no_argument,       NULL, 'a' },
    { "ack-en",   no_argument,       NULL, 'A' },
    { "push-lead",required_argument, NULL, 'L' },
    { "stop-lead",required_argument, NULL, 'T' },
    { "rd-cap",   required_argument, NULL, 'R' },
    { "gap-us",   required_argument, NULL, 'g' },
    { "recover",  no_argument,       NULL, 'r' },
    { "quiet",    no_argument,       NULL, 'q' },
    { NULL, 0, NULL, 0 }
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
  {
    switch (opt)
    {
      case 'p': flow = "probe"; break;
      case 'c': flow = "cmd"; arg_id = (int)strtol(optarg, NULL, 0); break;
      case 'C': arg_param = (int)strtol(optarg, NULL, 0); break;
      case 'V': flow = "ver"; break;
      case 's': flow = "stats"; arg_stats = (int)strtol(optarg, NULL, 0); break;
      case 'S': arg_len = (int)strtol(optarg, NULL, 0); if (!flow) flow = "send"; break;
      case 'D': arg_len = (int)strtol(optarg, NULL, 0); if (!flow) flow = "diag"; break;
      case 'M': flow = "stream"; break;
      case 'U': flow = "concurrent"; break;
      case 'Y': flow = "rate-up"; break;
      case 'W': flow = "rate-down"; break;
      case 'X': flow = "rate-concurrent"; break;
      case 'Q': flow = "rate-loop"; break;
      case '9': verify = 1; break;
      case '8': flow = "loop-sweep"; break;
      case '7': loop_lens = optarg; break;
      case '6': loop_ms = (int)strtol(optarg, NULL, 0); break;
      case '5': loop_desc = 1; break;
      case '4': loop_window = (int)strtol(optarg, NULL, 0); break;
      case '3': loop_step = (int)strtol(optarg, NULL, 0); break;
      case 'Z': arg_seconds = (int)strtol(optarg, NULL, 0); break;
      case '1': arg_depth = (int)strtol(optarg, NULL, 0); break;
      case '2': arg_xfer = (int)strtol(optarg, NULL, 0); break;
      case 'w': flow = "sweep"; break;
      case 'b': blocks_per = (int)strtol(optarg, NULL, 0); break;
      case 'l': nlen = parse_int_list(optarg, lens, (int)ARRAY_SIZE(lens)); break;
      case 'P': pattern = strcmp(optarg, "prbs") ? 0 : 1; break;
      case 'e': echo = 1; break;
      case 'a': ack_req = 1; break;
      case 'A': ack_en = 1; break;
      case 'L': push_lead = (int)strtol(optarg, NULL, 0);
                if (push_lead < 0) push_lead = 0;
                if (push_lead > 3) push_lead = 3;
                break;
      case 'T': stop_lead = (int)strtol(optarg, NULL, 0);
                if (stop_lead < 0) stop_lead = 0;
                if (stop_lead > 15) stop_lead = 15;
                break;
      case 'R': rd_cap = (int)strtol(optarg, NULL, 0);
                if (rd_cap < 0) rd_cap = 0;
                if (rd_cap > 15) rd_cap = 15;
                break;
      case 'g': gap_us = (int)strtol(optarg, NULL, 0); break;
      case 'r': recover = 1; break;
      case 'q': g_quiet = 1; break;
      default: usage(argv[0]); return 2;
    }
  }
  if (!flow)
  {
    usage(argv[0]);
    return 2;
  }

  ctx c;
  memset(&c, 0, sizeof(c));
  dev_open(&c);
  dev_drain(&c);

  int rc = 0;
  if (ack_en || push_lead || stop_lead || rd_cap)
  {
    u32 cfg = (ack_en ? 1u : 0u) | ((u32)push_lead << 1) |
              ((u32)stop_lead << 4) | ((u32)rd_cap << 16);
    if (send_cmd_wait(&c, CMD_BULK_SET_CFG, cfg, 500) < 0)
      die("SET_BULK_CFG failed");
  }
  if (!strcmp(flow, "probe"))
  {
    rc = flow_probe(&c) == 0 ? 0 : 1;
  }
  else if (!strcmp(flow, "cmd"))
  {
    rc = send_cmd_wait(&c, (u8)arg_id, (u32)arg_param, 2000) == 0 ? 0 : 1;
    if (rc == 0)
      printf("cmd 0x%02x param 0x%x acked\n", arg_id, arg_param);
  }
  else if (!strcmp(flow, "ver"))
  {
    int acks0 = c.acks;
    if (send_cmd_wait(&c, UHSIF_CMD_RESET, 0, 2000) < 0)
      rc = 1;
    else
    {
      u32 w2 = c.last_ack_w2;
      printf("block header: w2=0x%08x VER=%u capturing=%u test=%u speed=%u\n",
             w2, w2 & 0x1fu, (w2 >> 18) & 1u, (w2 >> 19) & 1u, (w2 >> 16) & 3u);
      printf("%s\n", ((w2 & 0x1fu) >= 3u) ? "bulk downlink supported (VER>=3)"
                                          : "bulk downlink NOT supported (VER<3)");
      if ((w2 & 0x1fu) < 3u)
        rc = 2;
    }
    (void)acks0;
  }
  else if (!strcmp(flow, "stats"))
  {
    u32 v = 0;
    if (get_stat(&c, arg_stats, &v) == 0)
      printf("stat[%d] = %u (0x%08x)\n", arg_stats, v, v);
    else
    {
      fprintf(stderr, "stats read failed\n");
      rc = 1;
    }
  }
  else if (!strcmp(flow, "rate-up"))
  {
    rc = flow_rate_up(&c, arg_seconds, arg_depth, arg_xfer);
  }
  else if (!strcmp(flow, "rate-down"))
  {
    rc = flow_rate_down(&c, arg_seconds, arg_depth, arg_xfer, pattern);
  }
  else if (!strcmp(flow, "rate-concurrent"))
  {
    rc = flow_rate_bidir(&c, arg_seconds, arg_depth, arg_xfer, pattern, 0, verify);
  }
  else if (!strcmp(flow, "loop-sweep"))
  {
    static int lens[8192];
    int n = loop_lens ? parse_len_spec(loop_lens, lens, (int)ARRAY_SIZE(lens), loop_step) : 0;
    if (n == 0)
      die("loop-sweep needs --loop-lens, e.g. \"4-1024,1028,1032\"");
    if (loop_desc)
      for (int a = 0, b = n - 1; a < b; a++, b--)
      {
        int t = lens[a]; lens[a] = lens[b]; lens[b] = t;
      }
    rc = flow_loop_sweep(&c, lens, n, loop_ms, arg_depth, 1, pattern, loop_window);
  }
  else if (!strcmp(flow, "rate-loop"))
  {
    rc = flow_rate_bidir(&c, arg_seconds, arg_depth, arg_xfer, pattern, 1, verify);
  }
  else if (!strcmp(flow, "diag"))
  {
    static const int idxs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    u32 v = 0;
    if (flow_send(&c, arg_len, pattern, 0, 0, NULL) != 0)
      rc = 1;
    sleep_ms(30);
    for (unsigned j = 0; j < sizeof(idxs) / sizeof(idxs[0]); j++)
    {
      if (get_stat(&c, idxs[j], &v) == 0)
        printf("stat[%d] = %u (0x%08x)\n", idxs[j], v, v);
      else
        printf("stat[%d] = <read failed>\n", idxs[j]);
    }
  }
  else if (!strcmp(flow, "stream"))
  {
    int N = blocks_per;
    u32 words0 = 0, blocks0 = 0, sum0 = 0, err0 = 0, esum_total = 0;
    get_stat(&c, 0, &words0);
    get_stat(&c, 1, &blocks0);
    get_stat(&c, 5, &sum0);
    get_stat(&c, 3, &err0);
    s64 t0 = now_ms();
    int fails = 0;
    for (int b = 0; b < N; b++)
    {
      u32 esum = 0;
      if (flow_send(&c, arg_len, pattern, ack_req, gap_us, &esum) != 0)
      {
        fails++;
        break;
      }
      esum_total += esum;
    }
    s64 dt = now_ms() - t0;
    sleep_ms(50);
    u32 words1 = 0, blocks1 = 0, sum1 = 0, err1 = 0;
    get_stat(&c, 0, &words1);
    get_stat(&c, 1, &blocks1);
    get_stat(&c, 5, &sum1);
    get_stat(&c, 3, &err1);
    int ok = (fails == 0) && ((u32)(words1 - words0) == (u32)N * (u32)arg_len) &&
             ((blocks1 - blocks0) == (u32)N) && ((sum1 - sum0) == esum_total) &&
             (err1 == err0);
    double mbps = (dt > 0) ? (double)((double)N * arg_len * 4.0) / (double)dt * 1000.0 / 1e6
                           : 0.0;
    printf("stream %d blocks x %d words: consumed=%u blocks=%u sum=%s err=%u %.1f MB/s%s\n",
           N, arg_len, words1 - words0, blocks1 - blocks0,
           (sum1 - sum0 == esum_total) ? "ok" : "BAD", err1 - err0, mbps,
           ok ? "  PASS" : "  FAIL");
    rc = ok ? 0 : 1;
  }
  else if (!strcmp(flow, "concurrent"))
  {
    int N = blocks_per;
    u32 words0 = 0, blocks0 = 0, sum0 = 0, err0 = 0, esum_total = 0;
    get_stat(&c, 0, &words0);
    get_stat(&c, 1, &blocks0);
    get_stat(&c, 5, &sum0);
    get_stat(&c, 3, &err0);
    if (send_cmd_wait(&c, UHSIF_CMD_TEST, 1, 500) < 0)
      die("TEST_MODE on failed");
    c.conc_mode = 1;
    c.conc_started = 0;
    int fails = 0;
    s64 t0 = now_ms();
    for (int b = 0; b < N; b++)
    {
      u32 esum = 0;
      if (flow_send(&c, arg_len, pattern, ack_req, gap_us, &esum) != 0)
      {
        fails++;
        break;
      }
      esum_total += esum;
      int n = dev_poll_in(&c, 0);
      if (n > 0)
        parse_blocks(&c);
    }
    s64 dt = now_ms() - t0;
    s64 dl = now_ms() + 400;
    while (now_ms() < dl)
    {
      int n = dev_poll_in(&c, 50);
      if (n > 0)
        parse_blocks(&c);
    }
    c.conc_mode = 0;
    send_cmd_wait(&c, UHSIF_CMD_TEST, 0, 500);
    u32 words1 = 0, blocks1 = 0, sum1 = 0, err1 = 0;
    get_stat(&c, 0, &words1);
    get_stat(&c, 1, &blocks1);
    get_stat(&c, 5, &sum1);
    get_stat(&c, 3, &err1);
    int down_ok = (fails == 0) && ((u32)(words1 - words0) == (u32)N * (u32)arg_len) &&
                  ((blocks1 - blocks0) == (u32)N) && ((sum1 - sum0) == esum_total);
    double down_mbps = (dt > 0) ? (double)((double)N * arg_len * 4.0) / (double)dt * 1000.0 / 1e6 : 0.0;
    double up_mbps = (dt > 0) ? (double)c.upl_bytes / (double)dt * 1000.0 / 1e6 : 0.0;
    printf("concurrent %d x %d words: down=%s %u/%u words err=%u (%.1f MB/s) | "
           "up=%lld B counter_err=%d hdr_err=%d (%.1f MB/s)%s\n",
           N, arg_len, down_ok ? "ok" : "BAD", words1 - words0, (u32)N * (u32)arg_len,
           err1 - err0, down_mbps, c.upl_bytes, c.conc_counter_err, c.errors,
           up_mbps, (down_ok && c.conc_counter_err == 0) ? "  PASS" : "  FAIL");
    rc = (down_ok && c.conc_counter_err == 0) ? 0 : 1;
  }
  else if (!strcmp(flow, "send"))
  {
    if (echo)
    {
      send_cmd_wait(&c, UHSIF_CMD_ENABLE, 0, 500);
      send_cmd_wait(&c, UHSIF_CMD_RESET, 1, 500);
      send_cmd_wait(&c, UHSIF_CMD_RESET, 0, 500);
      if (send_cmd_wait(&c, CMD_BULK_SET_CFG, 1u << 20, 500) < 0)
        die("SET_BULK_CFG echo_en failed");
      sleep_ms(20);        // 等 echo 源切换/FIFO 复位释放稳定
      c.echo_enable = 1;
    }
    rc = flow_send(&c, arg_len, pattern, ack_req, gap_us, NULL) == 0 ? 0 : 1;
    if (rc == 0)
      printf("send %d words: %s\n", arg_len, echo ? "echo PASS" : "written");
  }
  else if (!strcmp(flow, "sweep"))
  {
    if (nlen == 0)
    {
      memcpy(lens, default_lens, sizeof(default_lens));
      nlen = (int)ARRAY_SIZE(default_lens);
    }
    if (echo)
    {
      send_cmd_wait(&c, UHSIF_CMD_ENABLE, 0, 500);
      send_cmd_wait(&c, UHSIF_CMD_RESET, 1, 500);
      send_cmd_wait(&c, UHSIF_CMD_RESET, 0, 500);
      if (send_cmd_wait(&c, CMD_BULK_SET_CFG, 1u << 20, 500) < 0)
        die("SET_BULK_CFG echo_en failed");
      sleep_ms(20);        // 等 echo 源切换/FIFO 复位释放稳定
      c.echo_enable = 1;
    }
    int fails = 0;
    for (int b = 0; b < blocks_per; b++)
      fails += flow_sweep(&c, lens, nlen, pattern, ack_req, echo);
    printf("sweep: %d/%d pass, %d errors\n", nlen * blocks_per - fails,
           nlen * blocks_per, c.errors);
    rc = fails ? 1 : 0;
  }

  if (ack_en || push_lead || stop_lead || rd_cap || echo)
    send_cmd_wait(&c, CMD_BULK_SET_CFG, 0u, 500);   // 清除 echo_en 等配置

  if (recover)
  {
    libusb_control_transfer(c.dev, 0x40, 0xE2, 500, 0, NULL, 0, 1000);
    printf("device soft-reset requested\n");
  }

  libusb_release_interface(c.dev, 0);
  libusb_close(c.dev);
  return rc;
}
