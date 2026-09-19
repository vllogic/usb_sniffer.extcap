// SPDX-License-Identifier: BSD-3-Clause

#include "pcapng.h"

#include <pthread.h>

#define PCAPNG_BLOCK_BUF_SIZE  4096

// ---------------------------------------------------------------------------
// 异步落盘：回调线程只把 pcapng 块 memcpy 进 1 MiB 暂存块，写线程负责 fwrite。
//
// 根因（见 docs/tasks/usb_capture_corruption_report.md §11.9-§11.14）：原实现在
// libusb 完成回调里直接 fwrite 到 FIFO/文件，当消费者（Wireshark）或磁盘变慢时该
// 调用阻塞，回调不再提交 URB ⇒ 传输池排空 ⇒ 回压顶到设备侧 ⇒ FPGA 采集 FIFO 溢出。
// 与 usbcap_fast 同法：热路径只 memcpy，写线程 + 预分配环形缓冲吸收消费者抖动。
// 队列满时才会阻塞生产者。缓冲要"够吸收消费者抖动、又别把实时性拖垮"：
// 原来 16 x 1 MiB = 16 MiB 的队列加上 64 MiB 原始队列共 ~80 MiB，@46 MB/s 意味着
// Wireshark 里的事件流会滞后 ~1.7 s，且 Stop 时这段未投递的数据会被丢掉。现改为
// 32 x 256 KiB = 8 MiB（单块更小 -> 暂存块内的延迟从 ~22 ms 降到 ~5 ms）。
// ---------------------------------------------------------------------------
#define WQ_SLOTS 32
#define WQ_CHUNK (256u << 10)

// Live-delivery bound: hand a partial staging chunk to the writer thread after
// this many ms of not filling it.  The staging chunk is 256 KiB, so without
// this a sparse / full-speed stream could sit unflushed for seconds (256 KiB is
// only reached in ~5 ms at 46 MB/s, but takes seconds to minutes at FS / idle
// rates) -- the live consumer (Wireshark) showed nothing, then got one burst.
// Flushing at this cadence bounds the display latency and the in-flight tail.
#define LIVE_FLUSH_MS 50

struct pcapng
{
  FILE  *fd;
  bool   begun;

  // Current block assembly buffer.
  u8     block[PCAPNG_BLOCK_BUF_SIZE];
  int    ptr;

  // Blocks written before pcapng_begin() are staged here until the SHB/IDB
  // headers are flushed to the file, preserving SHB-first ordering even if
  // the device starts streaming right after the FPGA gets enabled.
  u8    *pend;
  int    pend_len;
  int    pend_cap;

  // 异步写状态
  u8    *chunk;                        // 当前 1 MiB 暂存块
  int    chunk_len;
  s64    chunk_ts;                     // ms when the current chunk was started
  u8    *q[WQ_SLOTS];                  // 待写队列
  size_t q_len[WQ_SLOTS];              // 每块的实际有效长度（尾块可能不满）
  int    q_head, q_tail, q_count;
  u8    *freeq[WQ_SLOTS];              // 预分配缓冲池（热路径零 malloc/free）
  int    free_n;
  pthread_mutex_t mu;
  pthread_cond_t  nonempty, nonfull, freecv;
  int    stop, wr_err;
  pthread_t tid;
};

//-----------------------------------------------------------------------------
static void *writer_main(void *arg)
{
  pcapng *p = (pcapng *)arg;

  for (;;)
  {
    pthread_mutex_lock(&p->mu);
    while (p->q_count == 0 && !p->stop)
      pthread_cond_wait(&p->nonempty, &p->mu);
    if (p->q_count == 0 && p->stop)
    {
      pthread_mutex_unlock(&p->mu);
      return NULL;
    }
    u8 *buf = p->q[p->q_head];
    size_t len = p->q_len[p->q_head];
    p->q_head = (p->q_head + 1) % WQ_SLOTS;
    p->q_count--;
    pthread_cond_signal(&p->nonfull);
    pthread_mutex_unlock(&p->mu);

    size_t off = 0;
    // 一次写整块有效长度；短写按需续写
    while (off < len)
    {
      size_t n = fwrite(buf + off, 1, len - off, p->fd);
      if (n == 0)
      {
        p->wr_err = 1;
        break;
      }
      off += n;
    }

    // Push the chunk out now.  Without this the CRT keeps small chunks in its
    // stdio buffer (observed 4096 B), so a live consumer only saw data once a
    // buffer's worth had accumulated or at close -- sparse output (a folded
    // full-speed stream emits ~200 B/s) stayed invisible for seconds.
    if (!p->wr_err)
      fflush(p->fd);

    pthread_mutex_lock(&p->mu);
    p->freeq[p->free_n++] = buf;
    pthread_cond_signal(&p->freecv);
    pthread_mutex_unlock(&p->mu);
  }
}

//-----------------------------------------------------------------------------
static u8 *buf_get_free(pcapng *p)
{
  pthread_mutex_lock(&p->mu);
  while (p->free_n == 0 && !p->wr_err)
    pthread_cond_wait(&p->freecv, &p->mu);
  u8 *b = p->free_n ? p->freeq[--p->free_n] : NULL;
  pthread_mutex_unlock(&p->mu);
  return b;
}

//-----------------------------------------------------------------------------
static void chunk_flush(pcapng *p)
{
  if (p->chunk_len == 0 || !p->chunk)
    return;

  pthread_mutex_lock(&p->mu);
  while (p->q_count == WQ_SLOTS && !p->wr_err)
    pthread_cond_wait(&p->nonfull, &p->mu);
  if (p->wr_err)
  {
    pthread_mutex_unlock(&p->mu);
    p->chunk_len = 0;
    return;
  }
  p->q[p->q_tail]   = p->chunk;
  p->q_len[p->q_tail] = (size_t)p->chunk_len;
  p->q_tail = (p->q_tail + 1) % WQ_SLOTS;
  p->q_count++;
  pthread_cond_signal(&p->nonempty);
  pthread_mutex_unlock(&p->mu);

  p->chunk = buf_get_free(p);
  p->chunk_len = 0;
  p->chunk_ts = os_get_time_ms();
}

//-----------------------------------------------------------------------------
// 把 n 字节交给写线程（热路径：memcpy，不落盘）
static void sink_write(pcapng *p, const u8 *d, int n)
{
  if (!p->begun || !p->fd || p->wr_err)
    return;

  while (n > 0)
  {
    if (!p->chunk)
    {
      p->chunk = buf_get_free(p);
      p->chunk_ts = os_get_time_ms();
    }
    if (!p->chunk)
    {
      p->wr_err = 1;
      return;
    }
    int room = (int)WQ_CHUNK - p->chunk_len;
    int take = n < room ? n : room;
    memcpy(p->chunk + p->chunk_len, d, (size_t)take);
    p->chunk_len += take;
    d += take;
    n -= take;
    if (p->chunk_len == (int)WQ_CHUNK)
      chunk_flush(p);
  }

  // Bound live delivery latency: flush a partial chunk once it has been open
  // for LIVE_FLUSH_MS.  At high rates the chunk fills and flushes first, so
  // this only fires for sparse traffic (where it is the difference between a
  // live display and a blank one).  sink_write() runs on the single producer
  // (raw-queue worker) thread, so touching p->chunk here is safe.
  if (p->chunk && p->chunk_len > 0 &&
      os_get_time_ms() - p->chunk_ts >= LIVE_FLUSH_MS)
    chunk_flush(p);
}

//-----------------------------------------------------------------------------
static void put_pad(pcapng *p)
{
  while (p->ptr % 4)
    p->block[p->ptr++] = 0;
}

//-----------------------------------------------------------------------------
static void put_half(pcapng *p, u16 value)
{
  p->block[p->ptr + 0] = (u8)value;
  p->block[p->ptr + 1] = (u8)(value >> 8);
  p->ptr += 2;
}

//-----------------------------------------------------------------------------
static void put_word(pcapng *p, u32 value)
{
  p->block[p->ptr + 0] = (u8)value;
  p->block[p->ptr + 1] = (u8)(value >> 8);
  p->block[p->ptr + 2] = (u8)(value >> 16);
  p->block[p->ptr + 3] = (u8)(value >> 24);
  p->ptr += 4;
}

//-----------------------------------------------------------------------------
static void put_data(pcapng *p, const u8 *data, int size)
{
  memcpy(&p->block[p->ptr], data, (size_t)size);
  p->ptr += size;
}

//-----------------------------------------------------------------------------
static void put_option(pcapng *p, int index, const char *str)
{
  int len = (int)strlen(str);

  put_half(p, (u16)index);
  put_half(p, (u16)len);
  put_data(p, (const u8 *)str, len);
  put_pad(p);
}

//-----------------------------------------------------------------------------
static void send_buffer(pcapng *p)
{
  int size = p->ptr + 4;

  put_word(p, (u32)size);         // trailing block total length word
  p->block[4] = (u8)size;         // patch the leading block total length
  p->block[5] = (u8)(size >> 8);
  p->block[6] = (u8)(size >> 16);
  p->block[7] = (u8)(size >> 24);

  if (p->begun)
  {
    sink_write(p, p->block, p->ptr);      // 交给写线程，回调不阻塞在落盘上
  }
  else
  {
    if (p->pend_len + p->ptr > p->pend_cap)
    {
      p->pend_cap = p->pend_cap ? p->pend_cap * 2 : 65536;
      p->pend = os_realloc(p->pend, p->pend_cap);
    }
    memcpy(&p->pend[p->pend_len], p->block, (size_t)p->ptr);
    p->pend_len += p->ptr;
  }

  p->ptr = 0;
}

//-----------------------------------------------------------------------------
static void write_block_type(pcapng *p, u32 type)
{
  put_word(p, type);
  put_word(p, 0); // block total length placeholder
}

//-----------------------------------------------------------------------------
static void write_file_header(pcapng *p)
{
  write_block_type(p, 0x0a0d0d0a);              // SHB
  put_word(p, 0x1a2b3c4d);                      // byte order magic
  put_half(p, 1);                               // major version
  put_half(p, 0);                               // minor version
  put_word(p, 0xffffffff);                      // section length (unknown)
  put_word(p, 0xffffffff);
  put_option(p, 0x0002, "USB Sniffer 2"); // shb_hardware
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
static void write_usb_header(pcapng *p, int link_type)
{
  write_block_type(p, 1);                       // IDB
  put_half(p, (u16)link_type);
  put_half(p, 0);                               // reserved
  put_word(p, 0xffff);                          // snap length
  put_option(p, 0x0002, "usb");                 // if_name
  put_option(p, 0x0003, "Hardware USB interface"); // if_description
  put_half(p, 9);                               // if_tsresol option code
  put_half(p, 1);                               // option length
  put_word(p, 9);                               // resolution = 10^-9 s
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
static void write_info_header(pcapng *p)
{
  write_block_type(p, 1);                       // IDB
  put_half(p, (u16)LINKTYPE_WIRESHARK_UPPER_PDU);
  put_half(p, 0);                               // reserved
  put_word(p, 0xffff);                          // snap length
  put_option(p, 0x0002, "info");                // if_name
  put_option(p, 0x0003, "Out of band information"); // if_description
  put_half(p, 9);                               // if_tsresol option code
  put_half(p, 1);                               // option length
  put_word(p, 9);                               // resolution = 10^-9 s
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
bool pcapng_write_failed(const pcapng *p)
{
  return p ? (p->wr_err != 0) : true;
}

//-----------------------------------------------------------------------------
pcapng *pcapng_open(const char *path)
{
  pcapng *p = os_alloc(sizeof(pcapng));

  p->fd = fopen(path, "wb");
  os_check(p->fd, "could not open FIFO pipe '%s'", path);

  // Buffered file IO: EPBs accumulate here (glibc allocates the buffer) and
  // hit the disk/pipe in large bursts instead of one fwrite() syscall per
  // frame.  capture_info() still calls pcapng_flush() on events, so the pipe
  // stays live for Wireshark.
  // 异步写线程初始化（缓冲池预分配）
  pthread_mutex_init(&p->mu, NULL);
  pthread_cond_init(&p->nonempty, NULL);
  pthread_cond_init(&p->nonfull, NULL);
  pthread_cond_init(&p->freecv, NULL);
  for (int i = 0; i < WQ_SLOTS; i++)
    p->freeq[i] = os_alloc(WQ_CHUNK);
  p->free_n = WQ_SLOTS;
  pthread_create(&p->tid, NULL, writer_main, p);

  return p;
}

//-----------------------------------------------------------------------------
void pcapng_begin(pcapng *p, int usb_link_type)
{
  os_assert(!p->begun);

  // Mark the stream begun before writing the section header: the header
  // blocks must go to the file/pipe directly, ahead of any pre-session EPBs
  // staged during the FPGA init phase (staging them would put the SHB after
  // those blocks and break the pcapng magic-first parse).
  p->begun = true;

  write_file_header(p);
  write_usb_header(p, usb_link_type);
  write_info_header(p);

  if (p->pend_len)
    sink_write(p, p->pend, p->pend_len);
}

//-----------------------------------------------------------------------------
void pcapng_write_epb(pcapng *p, u64 ts, const u8 *data, int size)
{
  write_block_type(p, 6);                       // EPB
  put_word(p, 0);                               // interface id 0
  put_word(p, (u32)(ts >> 32));                 // timestamp upper
  put_word(p, (u32)ts);                         // timestamp lower
  put_word(p, (u32)size);                       // captured packet length
  put_word(p, (u32)size);                       // original packet length
  put_data(p, data, size);
  put_pad(p);
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
void pcapng_write_info(pcapng *p, u64 ts, const char *str, int size)
{
  static const u8 hdr[] = { 0, 12, 0, 6, 's', 'y', 's', 'l', 'o', 'g', 0, 0, 0, 0 };

  write_block_type(p, 6);                       // EPB
  put_word(p, 1);                               // interface id 1
  put_word(p, (u32)(ts >> 32));                 // timestamp upper
  put_word(p, (u32)ts);                         // timestamp lower
  put_word(p, (u32)(sizeof(hdr) + size));       // captured packet length
  put_word(p, (u32)(sizeof(hdr) + size));       // original packet length
  put_data(p, hdr, sizeof(hdr));
  put_data(p, (const u8 *)str, size);
  put_pad(p);
  send_buffer(p);

  // Info records are the live "events" (folded-batch summaries, line state,
  // errors, stop reason).  Hand the staging chunk to the writer as soon as one
  // is written: a folded full-speed stream produces only one such record per
  // second, and waiting for a later packet write (or for the 256 KiB chunk to
  // fill) held it back until another record arrived.
  chunk_flush(p);
}

//-----------------------------------------------------------------------------
void pcapng_flush(pcapng *p)
{
  if (!p->begun || !p->fd)
    return;

  chunk_flush(p);                       // 让当前暂存块进入队列

  pthread_mutex_lock(&p->mu);
  while (p->q_count != 0 && !p->wr_err)
    pthread_cond_wait(&p->freecv, &p->mu);   // 队列写空（写线程会把缓冲放回 freeq）
  pthread_mutex_unlock(&p->mu);

  fflush(p->fd);
}

//-----------------------------------------------------------------------------
void pcapng_close(pcapng *p)
{
  if (p->fd)
  {
    pcapng_flush(p);                    // 已排空队列并 fflush

    pthread_mutex_lock(&p->mu);
    p->stop = 1;
    pthread_cond_signal(&p->nonempty);
    pthread_mutex_unlock(&p->mu);
    pthread_join(p->tid, NULL);

    if (p->chunk) { os_free(p->chunk); p->chunk = NULL; }
    for (int i = 0; i < p->free_n; i++) os_free(p->freeq[i]);
    pthread_mutex_destroy(&p->mu);
    pthread_cond_destroy(&p->nonempty);
    pthread_cond_destroy(&p->nonfull);
    pthread_cond_destroy(&p->freecv);

    fclose(p->fd);
  }

  os_free(p->pend);
  os_free(p);
}