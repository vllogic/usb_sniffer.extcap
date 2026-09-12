// SPDX-License-Identifier: BSD-3-Clause
// libusb transport backend for the CH32H417 UHSIF byte pipe.
//
//   EP1 OUT (0x01): 16-byte command packets (see cmd.c)
//   EP1 IN  (0x81): continuous upstream blocks when the FPGA FIFO reaches
//                   its watermark (16 bytes of block header + payload)
//
// The CH32 firmware is a zero-semantics bridge: whatever the FPGA writes to
// the UHSIF line 0 is DMA'd onto EP1 IN verbatim, and whatever arrives on
// EP1 OUT is written to UHSIF line 1 verbatim.

#include "transport.h"
#include "transport_internal.h"
#include "device.h"
#include <libusb.h>

#define USB_VID          0x1209
#define USB_PID          0x6688

#define EP_IN            0x81
#define EP_OUT           0x01
// 主机侧 IN 传输池: 16 x 256KiB (总 4MiB)。实测在 Windows 独立抓取(读 32MB)
// 下 overflow 最低(118, 相比旧 8x256KB 的 174), 且内存仅 4MiB; 参考实现的
// 32x16MiB(512MiB) 并无更好表现。Linux 同样适用(低于 usbfs_memory_mb 16MB)。
#define TRANSFER_SIZE    (256 * 1024)           // 256 KiB per IN transfer
#define TRANSFER_COUNT   16
#define TRANSFER_TIMEOUT 1000                   // ms

// 同步读/命令/探测缓冲上限: 不可沿用 16MiB 的异步池长度做同步
// libusb_bulk_transfer(), Windows 下会崩溃/极不稳定。
#define SYNC_BUF_SIZE    (256 * 1024)           // 256 KiB

// Pool of OUT transfers (commands are tiny and rare).
#define OUT_POOL_SIZE    4
#define OUT_PACKET_MAX   64

// Link-bandwidth probe: transient async IN pool used only during startup
// (before stream_mode()).  Counts bytes only -- the feed callback is NOT
// invoked, so probe traffic never enters the stream/packet pipeline.
#define PROBE_COUNT      8
#define PROBE_SIZE       (256 * 1024)

typedef struct probe_ctx
{
  libusb_device_handle    *handle;
  struct libusb_transfer  *tr[PROBE_COUNT];
  u8                      *buf[PROBE_COUNT];
  volatile s64            bytes;
  volatile bool           stop;
} probe_ctx;

typedef struct out_slot
{
  bool                 busy;
  struct libusb_transfer *transfer;
  u8                   data[OUT_PACKET_MAX];
} out_slot;

typedef struct
{
  libusb_device_handle *handle;
  struct libusb_transfer *in_transfers[TRANSFER_COUNT];
  u8                    *in_buffers[TRANSFER_COUNT];
  out_slot              out_pool[OUT_POOL_SIZE];
  u8                    *cmd_buf;      // command-phase sync read buffer
  bool                  alive;
  bool                  streams_up;
  bool                  closing;       // teardown: callbacks must not resubmit
} libusb_priv;

//-----------------------------------------------------------------------------
static void out_callback(struct libusb_transfer *transfer)
{
  out_slot *slot = (out_slot *)transfer->user_data;

  if (transfer->status != LIBUSB_TRANSFER_COMPLETED && slot->busy)
    log_print("usb: EP1 OUT transfer failed: %d", (int)transfer->status);

  slot->busy = false;
}

//-----------------------------------------------------------------------------
static void LIBUSB_CALL in_callback(struct libusb_transfer *transfer)
{
  transport *t = (transport *)transfer->user_data;
  libusb_priv *p = (libusb_priv *)t->priv;
  int rc;

  // Teardown: tl_close() has set closing before cancelling the pool.  Drop
  // everything at the top: a transfer that completed before the cancel still
  // delivers its buffer during the drain loop, and the stream/packet layers
  // have already been deleted by then -- feeding them is a use-after-free.
  if (p->closing)
    return;

  if (transfer->status == LIBUSB_TRANSFER_COMPLETED)
  {
    if (transfer->actual_length > 0 && t->cb.feed)
      t->cb.feed(t->cb.feed_user, transfer->buffer, transfer->actual_length);
  }
  else if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE)
  {
    log_print("usb: device disconnected");
    p->alive = false;
    return;
  }
  else if (transfer->status == LIBUSB_TRANSFER_CANCELLED)
  {
    // Shutdown path: tl_close() cancelled the pool, do not resubmit.
    return;
  }
  else if (transfer->status == LIBUSB_TRANSFER_ERROR)
  {
    log_print("usb: EP1 IN transfer error, retrying");
  }

  rc = libusb_submit_transfer(transfer);
  if (rc < 0)
  {
    log_print("usb: libusb_submit_transfer() failed: %s", libusb_error_name(rc));
    p->alive = false;
  }
}

//-----------------------------------------------------------------------------
static void tl_submit_in_pool(transport *t)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  int rc;

  if (!p->handle || p->streams_up)
    return;

  int armed = 0;

  for (int i = 0; i < TRANSFER_COUNT; i++)
  {
    p->in_buffers[i] = os_alloc(TRANSFER_SIZE);
    p->in_transfers[i] = libusb_alloc_transfer(0);

    if (!p->in_buffers[i] || !p->in_transfers[i])
    {
      log_print("usb: alloc %d/%d failed (buf/transfer), skipping", i, TRANSFER_COUNT);
      if (p->in_transfers[i]) libusb_free_transfer(p->in_transfers[i]);
      if (p->in_buffers[i])   os_free(p->in_buffers[i]);
      p->in_transfers[i] = NULL;
      p->in_buffers[i] = NULL;
      continue;
    }

    libusb_fill_bulk_transfer(p->in_transfers[i], p->handle, EP_IN,
        p->in_buffers[i], TRANSFER_SIZE, in_callback, t, TRANSFER_TIMEOUT);

    rc = libusb_submit_transfer(p->in_transfers[i]);
    if (rc < 0)
    {
      // 非致命: 大缓冲可能超出驱动可挂起上限, 降级为已成功提交的数量。
      log_print("usb: submit_transfer %d/%d failed: %s, skipping",
                i, TRANSFER_COUNT, libusb_error_name(rc));
      libusb_free_transfer(p->in_transfers[i]);
      p->in_transfers[i] = NULL;
      os_free(p->in_buffers[i]);
      p->in_buffers[i] = NULL;
      continue;
    }
    armed++;
  }

  log_print("usb: armed %d/%d IN transfers (%u KiB each)",
            armed, TRANSFER_COUNT, (unsigned)(TRANSFER_SIZE / 1024));

  if (armed == 0)
    os_error("usb: could not arm any IN transfer");

  p->streams_up = true;
}

//-----------------------------------------------------------------------------
static bool tl_open(transport *t)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  int rc = libusb_init(NULL);

  if (rc < 0)
    os_error("libusb_init(): %s", libusb_error_name(rc));

  libusb_device_handle *handle = NULL;

  // Retry-bounded scan: the previous session ends with a device soft reset
  // (0xE2), so a session started right after may hit the re-enumeration
  // gap (the device briefly disappears from the bus).  Poll for up to 5 s.
  for (int attempt = 0; attempt < 50 && !handle; attempt++)
  {
    libusb_device **devices = NULL;

    int count = libusb_get_device_list(NULL, &devices);
    if (count < 0)
      os_error("libusb_get_device_list(): %s", libusb_error_name(count));

    for (int i = 0; i < count; i++)
    {
      libusb_device *dev = devices[i];
      struct libusb_device_descriptor desc;

      if (libusb_get_device_descriptor(dev, &desc) < 0)
        continue;

      if (device_is_gen2(desc.idVendor, desc.idProduct, desc.bcdDevice))
      {
        if (libusb_open(dev, &handle) < 0)
          continue;
        break;
      }
    }

    libusb_free_device_list(devices, 1);

    if (!handle && attempt < 49)
      os_sleep(100);
  }

  if (!handle)
  {
    libusb_exit(NULL);
    os_error("could not open the capture device (VID %04x:PID %04x)", USB_VID, USB_PID);
  }

  p->handle = handle;

  p->cmd_buf = os_alloc(SYNC_BUF_SIZE);

  libusb_set_auto_detach_kernel_driver(handle, 1);
  rc = libusb_claim_interface(handle, 0);
  if (rc < 0)
    os_error("libusb_claim_interface(): %s", libusb_error_name(rc));

  p->alive = true;

  log_print("usb: device opened (EP1 IN/OUT)");

  return true;
}

//-----------------------------------------------------------------------------
// Drain whatever the device still buffers on EP1 IN (blocks left over from a
// previous session that was killed mid-capture) and discard it.  Called while
// the FPGA is stopped (Enable 0 / Reset 1 already sent), so no fresh data is
// produced; a timeout means the endpoint is empty.  Same model as the
// reference plugin's usb_flush_data().
static void tl_discard(transport *t)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  u8 *buf;
  int rc, size;
  int drained = 0;
  int full_reads = 0;
  bool saw_timeout = false;

  if (!p->handle)
    return;

  buf = os_alloc(SYNC_BUF_SIZE);

  for (int k = 0; k < 50; k++)
  {
    rc = libusb_bulk_transfer(p->handle, EP_IN, buf, SYNC_BUF_SIZE, &size, 20);

    if (rc == LIBUSB_ERROR_TIMEOUT)
    {
      saw_timeout = true;
      break;
    }
    else if (rc == LIBUSB_ERROR_NO_DEVICE)
    {
      log_print("usb: device disconnected during discard");
      p->alive = false;
      break;
    }
    else if (rc < 0)
      log_print("usb: discard read error: %s", libusb_error_name(rc));
    else
    {
      drained += size;
      if (size == SYNC_BUF_SIZE)
        full_reads++;
    }
  }

  os_free(buf);

  // Reaching the read-count cap without ever seeing an empty endpoint means
  // the FPGA was still producing data: Enable 0 / Reset 1 did not take
  // effect (or never arrived), so the flush is incomplete.
  if (!saw_timeout)
    log_print("usb: WARNING stale-data flush incomplete (%d bytes in %d full reads), FPGA stop did not take effect",
              drained, full_reads);
  else
    log_print("usb: upstream stale data flushed (%d bytes)", drained);
}

//-----------------------------------------------------------------------------
static void tl_stream_mode(transport *t)
{
  // Start the EP1 IN async pool.  Deferred until here so that the command /
  // discard phase runs without any upstream data entering the pipeline; only
  // after the stale-data flush does the (clean) capture stream start flowing.
  tl_submit_in_pool(t);
}

//-----------------------------------------------------------------------------
static bool tl_events(transport *t, long timeout_ms)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  struct timeval tv;
  int rc;

  for (;;)
  {
    if (!p->alive)
      return false;

    if (!p->streams_up)
    {
      // Command phase (async IN pool not started yet): read synchronously
      // with a bounded timeout and feed whatever arrives (the command
      // acknowledgements) into the stream layer.  A timeout means no ACK
      // yet; the caller keeps pumping until its deadline.
      int size;

      rc = libusb_bulk_transfer(p->handle, EP_IN, p->cmd_buf, SYNC_BUF_SIZE,
                                &size, timeout_ms);

      if (rc == LIBUSB_ERROR_TIMEOUT)
      {
        // A libusb timeout cancels the URB but retains whatever bytes were
        // already received; feed them so a partially-read ACK is not lost.
        if (size > 0 && t->cb.feed)
          t->cb.feed(t->cb.feed_user, p->cmd_buf, size);
        return true;
      }
      if (rc == LIBUSB_ERROR_NO_DEVICE)
      {
        log_print("usb: device disconnected");
        p->alive = false;
        return false;
      }
      if (rc < 0)
      {
        log_print("usb: command-phase read error: %s", libusb_error_name(rc));
        p->alive = false;
        return false;
      }
      if (size > 0 && t->cb.feed)
        t->cb.feed(t->cb.feed_user, p->cmd_buf, size);

      return true;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = libusb_handle_events_timeout(NULL, &tv);

    if (rc == LIBUSB_ERROR_INTERRUPTED)
      continue;

    if (rc < 0 && rc != LIBUSB_ERROR_TIMEOUT)
    {
      log_print("usb: libusb_handle_events() failed: %s", libusb_error_name(rc));
      p->alive = false;
      return false;
    }

    return true;
  }
}

//-----------------------------------------------------------------------------
static int tl_write(transport *t, const u8 *data, int size)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  out_slot *slot = NULL;

  if (size > OUT_PACKET_MAX)
    os_error("usb: internal error, command packet too large");

  for (int i = 0; i < OUT_POOL_SIZE; i++)
  {
    if (!p->out_pool[i].busy)
    {
      slot = &p->out_pool[i];
      break;
    }
  }

  if (!slot)
  {
    log_print("usb: EP1 OUT pool exhausted, dropping command");
    return -1;
  }

  if (!slot->transfer)
  {
    slot->transfer = libusb_alloc_transfer(0);
    os_check(slot->transfer, "libusb_alloc_transfer()");
  }

  memcpy(slot->data, data, (size_t)size);
  slot->busy = true;

  libusb_fill_bulk_transfer(slot->transfer, p->handle, EP_OUT,
      slot->data, size, out_callback, slot, 100);

  int rc = libusb_submit_transfer(slot->transfer);
  if (rc < 0)
  {
    slot->busy = false;
    log_print("usb: EP1 OUT submit failed: %s", libusb_error_name(rc));
    return rc;
  }

  return 0;
}

//-----------------------------------------------------------------------------
static void LIBUSB_CALL probe_in_callback(struct libusb_transfer *transfer)
{
  probe_ctx *pc = (probe_ctx *)transfer->user_data;

  if (transfer->status == LIBUSB_TRANSFER_COMPLETED)
    pc->bytes += transfer->actual_length;

  if (transfer->status == LIBUSB_TRANSFER_CANCELLED)
    return;

  if (pc->stop)
    return;

  int rc = libusb_submit_transfer(transfer);
  if (rc < 0)
    log_print("usb: probe IN resubmit failed: %s", libusb_error_name(rc));
}

//-----------------------------------------------------------------------------
// Uplink bandwidth probe: run a transient async IN pool for window_ms and
// return the number of bytes received.  The feed callback is not invoked
// (the FPGA test-mode counter-fill is not capture traffic).  Returns -1 if
// the device is gone.  Must run before stream_mode() (the main IN pool is
// not started yet, so the probe's transfers do not collide with it).
static s64 tl_probe_upstream(transport *t, long window_ms)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  probe_ctx pc = { 0 };
  int rc;

  if (!p->handle)
    return -1;

  pc.handle = p->handle;

  for (int i = 0; i < PROBE_COUNT; i++)
  {
    pc.buf[i] = os_alloc(PROBE_SIZE);
    pc.tr[i] = libusb_alloc_transfer(0);
    os_check(pc.tr[i], "libusb_alloc_transfer() (probe)");

    libusb_fill_bulk_transfer(pc.tr[i], p->handle, EP_IN,
        pc.buf[i], PROBE_SIZE, probe_in_callback, &pc, TRANSFER_TIMEOUT);

    rc = libusb_submit_transfer(pc.tr[i]);
    if (rc < 0)
    {
      log_print("usb: probe IN submit failed: %s", libusb_error_name(rc));
      break;
    }
  }

  s64 deadline = os_get_time_ms() + window_ms;

  while (os_get_time_ms() < deadline)
  {
    struct timeval tv = { 0, 20000 };
    libusb_handle_events_timeout(NULL, &tv);
  }

  pc.stop = true;

  for (int i = 0; i < PROBE_COUNT; i++)
    if (pc.tr[i])
      libusb_cancel_transfer(pc.tr[i]);

  // Drain until every probe transfer ran its callback (bytes are final).
  for (int spin = 0; spin < 50; spin++)
  {
    struct timeval tv = { 0, 10000 };
    libusb_handle_events_timeout(NULL, &tv);
  }

  s64 got = pc.bytes;

  for (int i = 0; i < PROBE_COUNT; i++)
  {
    if (pc.tr[i])
    {
      libusb_free_transfer(pc.tr[i]);
      os_free(pc.buf[i]);
    }
  }

  log_print("usb: probe window %ld ms read %lld bytes", window_ms, got);

  return got;
}

//-----------------------------------------------------------------------------
static bool tl_alive(const transport *t)
{
  libusb_priv *p = (libusb_priv *)t->priv;
  return p->alive;
}

//-----------------------------------------------------------------------------
static void tl_close(transport *t)
{
  libusb_priv *p = (libusb_priv *)t->priv;

  if (p->handle)
  {
    // Session-end device soft reset (EP0 vendor request 0xE2, same path as
    // iap_cli.py reset): the CH32 firmware's upstream counters only ever
    // grow, so EP1 can stall after many capture sessions.  The reset also
    // kills any in-flight URBs, which the closing flag below absorbs.
    // Errors are tolerated: if the firmware rejects the request, teardown
    // still completes and the next session just starts from the stalled
    // state (recoverable with iap_cli.py reset).
    int rc = libusb_control_transfer(p->handle,
        LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
        0xE2, 0/*delay ms*/, 0/*wIndex*/, NULL, 0, 100);

    if (rc < 0)
      log_print("usb: session-end reset request failed: %s", libusb_error_name(rc));

    p->closing = true;   // in_callback() must not resubmit during teardown

    // OUT pool: a command issued right before teardown may still be in
    // flight.  libusb requires cancellation before free; the shared drain
    // loop below lets out_callback() run and release the slot.  Cancel
    // errors are ignored: after the session-end reset above the device may
    // already be re-enumerating (NOT_FOUND / NO_DEVICE), in which case the
    // transfer is either already complete or gone with the bus.
    for (int i = 0; i < OUT_POOL_SIZE; i++)
    {
      if (p->out_pool[i].transfer && p->out_pool[i].busy)
        libusb_cancel_transfer(p->out_pool[i].transfer);
    }

    for (int i = 0; i < TRANSFER_COUNT; i++)
    {
      if (p->in_transfers[i])
        libusb_cancel_transfer(p->in_transfers[i]);
    }

    // Drain the event loop until every cancelled transfer ran its callback;
    // otherwise libusb_exit() below races the callback thread (mutex assert).
    for (int spin = 0; spin < 50; spin++)
    {
      struct timeval tv = { 0, 10000 };
      libusb_handle_events_timeout(NULL, &tv);
    }

    for (int i = 0; i < TRANSFER_COUNT; i++)
    {
      if (p->in_transfers[i])
      {
        libusb_free_transfer(p->in_transfers[i]);
        os_free(p->in_buffers[i]);
      }
    }

    for (int i = 0; i < OUT_POOL_SIZE; i++)
    {
      if (p->out_pool[i].transfer)
        libusb_free_transfer(p->out_pool[i].transfer);
    }

    os_free(p->cmd_buf);

    libusb_release_interface(p->handle, 0);
    libusb_close(p->handle);
    libusb_exit(NULL);
  }

  os_free(p);
}

//-----------------------------------------------------------------------------
transport *transport_libusb_new(const transport_callbacks *cb)
{
  transport *t = os_alloc(sizeof(transport));
  static const transport_ops ops =
  {
    .open = tl_open,
    .discard = tl_discard,
    .stream_mode = tl_stream_mode,
    .events = tl_events,
    .write = tl_write,
    .alive = tl_alive,
    .close = tl_close,
    .probe_upstream = tl_probe_upstream,
  };

  t->cb = *cb;
  t->priv = os_alloc(sizeof(libusb_priv));
  t->ops = (transport_ops *)&ops;

  return t;
}