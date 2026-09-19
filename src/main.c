// SPDX-License-Identifier: BSD-3-Clause
// Merged USB Sniffer Wireshark extcap plugin entry point.
//
// One interface, two capture engines behind it; the engine is chosen
// automatically at session start by probing VID/PID + bcdDevice:
//
//   gen1 (ataradov-class analyzer): FX2LP + FPGA, EP 0x82 raw frame stream,
//        vendor-request control plane, plus the firmware maintenance tools
//        (--mcu-*/--fpga-*).
//   gen2 (Vllogic USB Sniffer 2):   CH32H417 UHSIF 4-word block protocol,
//        EP1 IN/OUT, acknowledged commands.
//
// Live mode:   capture_usb_vllogic --capture --fifo <pipe> [--speed ..] [--fold] ...
// Offline:     capture_usb_vllogic --replay <stream.bin> --fifo <out.pcapng> ...

#include "os_common.h"
#include "extcap.h"
#include "pcapng.h"
#include "stream.h"
#include "cmd.h"
#include "packet.h"
#include "transport.h"
#include "uhsif.h"
#include "capture_defs.h"
#include "device.h"
#include "gen1/usb.h"
#include "gen1/capture.h"
#include "gen1/fx2lp.h"
#include "gen1/fpga.h"

#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// Windows (MSYS2/MinGW): the CRT defaults stdout/stderr to text mode, which
// converts '\n' to "\r\n" and corrupts the extcap protocol stream (paths,
// dlt/arg values) consumed by Wireshark.  Force binary mode at startup.
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
static void os_set_binary_io(void)
{
  _setmode(_fileno(stdout), _O_BINARY);
  _setmode(_fileno(stderr), _O_BINARY);
}
#else
static void os_set_binary_io(void)
{
}
#endif

volatile sig_atomic_t g_stop = 0;

static void sig_handler(int signum)
{
  (void)signum;
  g_stop = 1;
}

//-----------------------------------------------------------------------------
// gen2 engine (unchanged from USB Sniffer 2).

static int dlt_for_speed(int speed)
{
  switch (speed)
  {
    case CaptureSpeed_LS: return LINKTYPE_USB_2_0_LOW_SPEED;
    case CaptureSpeed_FS: return LINKTYPE_USB_2_0_FULL_SPEED;
    case CaptureSpeed_HS: return LINKTYPE_USB_2_0_HIGH_SPEED;
    default:              return LINKTYPE_USB_2_0;
  }
}

//-----------------------------------------------------------------------------
// Decouple the USB event loop from the interpretation/pcapng pipeline.
//
// The transport callback used to run stream_feed()->packet_feed()->pcapng_write
// inline.  A live consumer (Wireshark) can stall for tens/hundreds of ms while
// it dissects or redraws; the pcapng ring then fills and pcapng_write blocks
// inside the libusb callback, which stops reaping/re-submitting URBs.  The
// device has only ~2.25 MiB of SRAM (~50 ms), so it overflows -> truncated
// frames -> the desync/toggle storm.  Writing to a plain file from the CLI
// never stalls, which is exactly why the same capture was clean there.
//
// Fix: the callback only memcpy()s into a raw-byte queue and returns
// immediately; a worker thread drains it through stream/packet/pcapng.
// Consumer stalls now back up this queue, not the URB servicing.
//
// Sizing is a latency <-> burst-tolerance trade-off: 32 x 256 KiB = 8 MiB here
// plus 8 MiB in pcapng = 16 MiB total.  That is ~0.35 s at 46 MB/s (still
// >6x the device's own 2.25 MiB/~50 ms elasticity), but unlike the first cut
// (64 MiB raw + 16 MiB pcapng) it does not make the Wireshark event stream lag
// ~1.7 s or drop a large in-flight tail when the user hits Stop right after a
// read.  A persistent consumer slower than the bus will still build a backlog
// up to this bound -- that is physical and cannot be buffered away.
#define RAWQ_CHUNK (256 * 1024)
#define RAWQ_SLOTS 32

typedef struct { u8 *buf; int len; } rawq_item;

typedef struct
{
  pthread_mutex_t mu;
  pthread_cond_t  nonempty, nonfull;
  rawq_item       q[RAWQ_SLOTS];
  int             head, tail, count;
  u8             *free_bufs[RAWQ_SLOTS];
  int             free_count;
  int             stop;
  stream         *stream;
  pthread_t       tid;
} rawq;

static void *rawq_thread(void *arg)
{
  rawq *r = (rawq *)arg;

  for (;;)
  {
    pthread_mutex_lock(&r->mu);
    while (0 == r->count && 0 == r->stop)
      pthread_cond_wait(&r->nonempty, &r->mu);
    if (0 == r->count && r->stop) { pthread_mutex_unlock(&r->mu); break; }

    rawq_item it = r->q[r->tail];
    r->tail = (r->tail + 1) % RAWQ_SLOTS;
    r->count--;
    pthread_cond_signal(&r->nonfull);
    pthread_mutex_unlock(&r->mu);

    stream_feed(r->stream, it.buf, it.len);

    pthread_mutex_lock(&r->mu);
    r->free_bufs[r->free_count++] = it.buf;
    pthread_mutex_unlock(&r->mu);
  }
  return NULL;
}

static bool rawq_init(rawq *r, stream *s)
{
  memset(r, 0, sizeof(*r));
  r->stream = s;
  pthread_mutex_init(&r->mu, NULL);
  pthread_cond_init(&r->nonempty, NULL);
  pthread_cond_init(&r->nonfull, NULL);
  for (int i = 0; i < RAWQ_SLOTS; i++)
  {
    r->free_bufs[i] = (u8 *)os_alloc(RAWQ_CHUNK);
    if (!r->free_bufs[i]) return false;
  }
  r->free_count = RAWQ_SLOTS;
  return pthread_create(&r->tid, NULL, rawq_thread, r) == 0;
}

static void rawq_push(rawq *r, const u8 *data, int size)
{
  int off = 0;

  while (off < size)
  {
    int n = size - off;
    if (n > RAWQ_CHUNK) n = RAWQ_CHUNK;

    pthread_mutex_lock(&r->mu);
    while (0 == r->free_count && 0 == r->stop)
      pthread_cond_wait(&r->nonfull, &r->mu);
    if (r->stop || 0 == r->free_count) { pthread_mutex_unlock(&r->mu); return; }
    u8 *b = r->free_bufs[--r->free_count];
    pthread_mutex_unlock(&r->mu);

    memcpy(b, data + off, (size_t)n);

    pthread_mutex_lock(&r->mu);
    r->q[r->head].buf = b;
    r->q[r->head].len = n;
    r->head = (r->head + 1) % RAWQ_SLOTS;
    r->count++;
    pthread_cond_signal(&r->nonempty);
    pthread_mutex_unlock(&r->mu);
    off += n;
  }
}

static void rawq_stop(rawq *r)
{
  pthread_mutex_lock(&r->mu);
  r->stop = 1;
  pthread_cond_broadcast(&r->nonempty);
  pthread_cond_broadcast(&r->nonfull);
  pthread_mutex_unlock(&r->mu);
  pthread_join(r->tid, NULL);
  for (int i = 0; i < r->free_count; i++)
    free(r->free_bufs[i]);
}

//-----------------------------------------------------------------------------
// Device-side callbacks (all run in the transport event loop).
typedef struct
{
  stream *stream;
  cmd    *cmd;
  packet *packet;
  rawq   *rq;
  int     async_feed;      // only the live data phase is decoupled; the
                           // acknowledged command phases need synchronous
                           // parse (cmd_exec() waits for the ACK callback)
} context;

static void feed_cb(void *user, const u8 *data, int size)
{
  context *cx = (context *)user;

  if (size <= 0)
    return;

  if (cx->async_feed)
    rawq_push(cx->rq, data, size);
  else
    stream_feed(cx->stream, data, size);
}

static void data_cb(void *user, const u8 *data, int size)
{
  context *cx = (context *)user;

  if (!cmd_input_suppressed(cx->cmd))
    packet_feed(cx->packet, data, size);

  // Parsing now runs on the raw-queue worker thread; wake the main loop if the
  // capture limit (or a fatal stream end) was reached there.
  if (packet_finished(cx->packet))
    g_stop = 1;
}

static void ack_cb(void *user)
{
  context *cx = (context *)user;
  cmd_ack_event(cx->cmd);
}

static void rsync_cb(void *user)
{
  context *cx = (context *)user;
  packet_rsync(cx->packet);
}

//-----------------------------------------------------------------------------
// Pre-session cleanup: stop the capture engine and flush whatever the FPGA /
// CH32 still hold from a previous session that was killed mid-capture
// (e.g. Wireshark pausing the capture kills the extcap process instantly).
// The stale blocks are drained by transport_discard() and never enter the
// stream layer.  Mirrors the reference plugin's usb_flush_data() placement
// (Enable 0 / Reset 1, then a synchronous drain, then clean start).
static void capture_stop_and_flush(cmd *c, transport *tr)
{
  cmd_tx_quiet(c, UHSIF_CMD_ENABLE, 0);   // stop capturing: no new data
  cmd_tx_quiet(c, UHSIF_CMD_RESET, 1);    // reset engine + clear capture FIFO

  // Let the FPGA apply the commands and push out in-flight blocks.  The
  // synchronous discard below drives the event loop internally, so the pending
  // OUT callbacks free their pool slots as it drains.
  os_sleep(20);

  transport_discard(tr);                  // drain stale ACKs + residual blocks
}

//-----------------------------------------------------------------------------
// Send the acknowledged FPGA init sequence.  Returns false on the first
// command that is never acknowledged, so the caller can recover (device reset)
// and retry once instead of aborting outright.
static bool capture_init_cmds(cmd *c, int speed)
{
  // Serialized init sequence mirroring the upstream plugin, mapped onto the
  // UHSIF command set.  The FPGA acknowledges every command with a 16-byte
  // ACK block before the next one is issued.  Runs only after the stale data
  // flush, so the upstream stream is clean and every ACK resolves promptly.
  struct { int id; u32 param; } init[] =
  {
    // Upload blocks at the protocol maximum (4092 words / 16 KiB) instead of
    // the FPGA power-on default of 1024 words (4 KiB).  With 4 KiB blocks the
    // upstream is throttled by per-block header/inter-block overhead plus a
    // USBSS TX chain re-arm per block (measured ~91 MB/s on SuperSpeed);
    // at 16 KiB blocks the same link reaches ~419 MB/s (the FPGA's RESET
    // command does not reset this register, so the setting survives ENABLE
    // 1 and the whole capture session).
    { UHSIF_CMD_UPLOAD_PARAMS, 4092 },
    { UHSIF_CMD_SPEED,  (u32)speed }, // Speed (0=LS 1=FS 2=HS 3=AUTO)
    { UHSIF_CMD_RESET,  0 },          // Reset 0
    { UHSIF_CMD_ENABLE, 1 },          // Enable 1
  };

  for (unsigned i = 0; i < ARRAY_SIZE(init); i++)
  {
    if (!cmd_exec(c, init[i].id, init[i].param))
    {
      log_print("cmd: 0x%02x(%u) no ACK", init[i].id, (unsigned)init[i].param);
      return false;
    }

    log_print("cmd: 0x%02x(%u) acknowledged", init[i].id, (unsigned)init[i].param);
  }

  return true;
}

//-----------------------------------------------------------------------------
// Startup link-bandwidth probe (gen2, live only): flash UHSIF TEST_MODE so
// the FPGA counter-fill loads the upstream pipe at the physical link rate,
// measure the received bytes over a short async window, stop and flush so
// the real capture starts clean.  The probe traffic never enters the
// stream/packet pipeline (feed callback is bypassed by the transport).
//
// Before measuring, bump the FPGA upload block size to the protocol maximum
// (CMD_UPLOAD_PARAMS = 4092 words / 16 KiB).  With the default 1024-word
// (4 KiB) blocks the upstream is throttled by per-block header/inter-block
// overhead plus a USBSS TX chain re-arm per block (measured ~91 MB/s on
// SuperSpeed); at 4092 words the same link reaches ~418 MB/s, matching the
// logic-analyzer project.  Realize the probe reports the physical link's
// best-case rate, not the 4 KiB-block capture-mode rate.
//
// Returns the measured MB/s, or a negative value when the probe is not
// supported / no bytes were read.
#define LINK_PROBE_MS   400
static double capture_speed_probe(cmd *c, transport *tr)
{
  // Quiet commands: do not alter the command-layer suppress state, so any
  // counter-fill bytes the FPGA pushes before the first real command are
  // still excluded from the upstream pipeline.
  cmd_tx_quiet(c, UHSIF_CMD_UPLOAD_PARAMS, 4092);  // 16 KiB blocks
  cmd_tx_quiet(c, UHSIF_CMD_TEST, 1);
  os_sleep(20);                            // let TEST mode take effect

  s64 bytes = transport_probe_upstream(tr, LINK_PROBE_MS);

  cmd_tx_quiet(c, UHSIF_CMD_TEST, 0);
  os_sleep(20);
  transport_discard(tr);                   // drain residual counter-fill blocks

  if (bytes <= 0)
  {
    log_print("link probe: no data received, skipped");
    return -1.0;
  }

  double mbps = (double)bytes * 1000.0 / (double)LINK_PROBE_MS / 1e6;

  log_print("link probe: %lld bytes over %d ms -> %.1f MB/s",
            bytes, LINK_PROBE_MS, mbps);

  return mbps;
}

//-----------------------------------------------------------------------------
static int run_capture_gen2(const packet_opts *popts)
{
  transport_callbacks tcb = { 0 };
  context cx = { 0 };

  pcapng *out = pcapng_open(g_opt.extcap_fifo ? g_opt.extcap_fifo : "out.pcapng");

  stream_callbacks scb;
  scb.data_cb = data_cb;
  scb.ack_cb = ack_cb;
  scb.rsync_cb = rsync_cb;
  scb.user = &cx;

  stream *stream = stream_new(&scb);

  cmd cmd;
  cmd_init(&cmd, NULL);   // transport attached below

  packet *packet = packet_new(popts, out);

  cx.stream = stream;
  cx.cmd = &cmd;
  cx.packet = packet;

  rawq rq;
  cx.rq = &rq;
  if (!rawq_init(&rq, stream))
  {
    log_print("raw queue init failed");
    return 1;
  }

  tcb.feed = feed_cb;
  tcb.feed_user = &cx;

  transport *tr;
  if (g_opt.replay)
    tr = transport_replay_new(&tcb, g_opt.replay);
  else
    tr = transport_libusb_new(&tcb);

  cmd.tr = tr;

  if (!transport_open(tr))
    os_error("could not open the capture transport");

  // Stop the engine and drain stale upstream data from the previous session
  // before the acknowledged init sequence.  During the command phase the
  // libusb transport reads the ACKs synchronously (no async pool yet) and
  // the replay transport stays in its 16-byte ACK phase.
  //
  // Recovery: on Windows right after a boot EP1 IN can come up wedged (the
  // first command never answers; see docs/tasks/set_configuration_ep1_wedge.md).
  // When the init sequence fails, soft-reset the device once and retry the
  // whole startup instead of aborting the capture.
  double link_mbps = -1.0;
  bool inited = false;

  for (int attempt = 0; attempt < 2 && !inited; attempt++)
  {
    capture_stop_and_flush(&cmd, tr);

    // Startup link-bandwidth probe (gen2 live only): flash TEST mode, measure
    // the achievable uplink rate in ~0.4 s, then restore a stopped/clean state.
    link_mbps = -1.0;
    if (!g_opt.replay)
      link_mbps = capture_speed_probe(&cmd, tr);

    inited = capture_init_cmds(&cmd, popts->capture_speed);

    if (!inited && attempt == 0)
    {
      log_print("startup: FPGA not responding, resetting device once");

      if (!transport_reset_device(tr))
        os_error("FPGA not responding and device reset is unavailable");

      cmd_init(&cmd, tr);        // seq/suppress/fatal after the device reboot
      os_sleep(200);
    }
  }

  if (!inited)
    os_error("FPGA did not acknowledge the init sequence after device reset");

  // Now that the FPGA is enabled, lay down the pcapng skeleton and flush any
  // buffered pre-session blocks, then enable the capture gate.
  pcapng_begin(out, dlt_for_speed(popts->capture_speed));

  // Report the measured link bandwidth as the very first record so Wireshark
  // surfaces it before any packet data.
  if (link_mbps >= 0.0)
  {
    char line[128];
    int len = snprintf(line, sizeof(line),
                       "Link bandwidth (uplink): %.1f MB/s", link_mbps);
    if (len > 0 && len < (int)sizeof(line))
    {
      pcapng_write_info(out, 0, line, len);
      pcapng_flush(out);
    }
  }

  // Research §11.17: the device's stall elasticity (~2.25 MiB pool + FIFOs
  // ≈ 50 ms @46 MB/s) and the 16-deep IN pool only pay off when the uplink
  // really runs in 16 KiB-block mode on SuperSpeed (~420 MB/s).  Two degraded
  // modes silently destroy that margin:
  //   * UPLOAD_PARAMS did not take effect -> 4 KiB blocks -> ~91-95 MB/s
  //     (each URB then short-terminates at 4 KiB, so the deep pool is useless);
  //   * the device enumerated on the USB2 half of the hub (480 Mbps, shared
  //     with the tapped bus) -> ~40-50 MB/s.
  // In both cases the host only has the pool's own ~50 ms, so surface it.
  if (link_mbps >= 0.0 && link_mbps < 150.0)
  {
    char warn[192];
    int len = snprintf(warn, sizeof(warn),
                       "WARNING: uplink degraded (%.1f MB/s < 150); expected ~420 MB/s "
                       "with 16 KiB blocks on SuperSpeed -- host stalls may drop packets",
                       link_mbps);
    if (len > 0 && len < (int)sizeof(warn))
    {
      log_print("%s", warn);
      pcapng_write_info(out, 0, warn, len);
      pcapng_flush(out);
    }
  }

  packet_announce(packet);

  // Build fingerprint: makes it obvious which binary Wireshark actually
  // loaded (the plugin must be copied into %APPDATA%\Wireshark\extcap\ and
  // Wireshark restarted; a stale copy silently keeps running otherwise).
  packet_info(packet, "Plugin build: " __DATE__ " " __TIME__);

  transport_stream_mode(tr);
  cx.async_feed = 1;          // data phase: decouple parse/pcapng from USB

  log_print("capture running");

  // Main event loop.
  while (!g_stop && transport_alive(tr) && !packet_finished(packet)
         && !pcapng_write_failed(out))
  {
    if (!transport_events(tr, 50))
      break;
  }

  log_print("capture finished");

  // Drain the raw queue and stop its worker before touching the transport
  // again: the session-end commands below need synchronous ACK parsing.
  rawq_stop(&rq);
  cx.async_feed = 0;

  // Record WHY the capture ended into the pcapng (if1).  "It stopped by
  // itself" must never be a mystery again: this distinguishes a host stop
  // (Wireshark Stop / stop-condition / signal), a lost uplink, the capture
  // limit, and a stream end.  packet_finished is checked before g_stop because
  // data_cb() also raises g_stop to wake this loop when the limit is reached,
  // which would otherwise mislabel a limit stop as a host stop.
  const char *why = packet_finished(packet) ? "capture limit reached"
                  : g_stop                  ? "host stop (Wireshark Stop / stop condition / signal)"
                  : pcapng_write_failed(out) ? "output pipe closed (consumer stopped reading)"
                  : !transport_alive(tr)     ? "uplink/device lost"
                  : "stream ended";
  log_print("capture finished: %s", why);
  packet_stop_info(packet, why);

  // 会话结束(用户 Stop / 信号 / 抓满)必须显式关闭 FPGA 捕获: 否则 FPGA 保持
  // capturing=1, 板载 RGB 会持续按速率闪烁, 与 Wireshark 已停止状态不一致。
  // 用带应答的命令确保真正送达后再关闭传输。
  if (transport_alive(tr))
  {
    if (!cmd_exec(&cmd, UHSIF_CMD_ENABLE, 0))
      cmd_tx_quiet(&cmd, UHSIF_CMD_ENABLE, 0);   // 退而求其次: 异步补发
    else
      log_print("capture disabled (FPGA capturing=0)");
    os_sleep(20);
    transport_events(tr, 20);
  }

  pcapng_close(out);
  packet_delete(packet);
  stream_delete(stream);
  transport_close(tr);

  return 0;
}

//-----------------------------------------------------------------------------
// gen1 engine.

static int run_capture_gen1(void)
{
  usb_init();
  capture_start();           // opens device, writes pcapng, streams to the
                             // end of the session (stop flag or limit)
  usb_close();
  return 0;
}

//-----------------------------------------------------------------------------
// gen1 maintenance tools (ported from upstream usb_sniffer.c).

static void maint_mcu_sram(const char *name)
{
  u8 *data;
  int size;

  usb_init();

  if (!usb_open(FX2LP_VID, FX2LP_PID, 0))
    os_error("could not open unconfigured FX2LP device");

  size = os_file_read_all(name, &data);

  printf("Uploading %d bytes into the FX2LP SRAM\n", size);
  fx2lp_sram_upload(data, size);
  printf("...done\n");

  os_free(data);
  usb_close();
  exit(0);
}

static void maint_mcu_eeprom(const char *name)
{
  u64 traceid;
  u8 *sn;
  u8 *data;
  int size;

  usb_init();
  open_capture_device();

  fpga_enable();
  traceid = fpga_read_traceid() & 0x00ffffffffffffff;
  fpga_disable();

  size = os_file_read_all(name, &data);

  sn = find_str(data, size, "[-----SN-----]");
  os_check(sn, "provided binary does not include a placeholder for the serial number");

  sprintf((char *)sn, "%014" PRIx64, traceid);

  printf("Programming %d bytes into the FX2LP EEPROM (SN: %s)\n", size, sn);
  fx2lp_eeprom_upload(data, size);
  printf("...done\n");

  usb_close();
  exit(0);
}

static void maint_fpga_program_sram(const char *name)
{
  u8 *data;
  int size = os_file_read_all(name, &data);

  printf("Uploading FPGA SRAM\n");
  usb_init();
  open_capture_device();
  fpga_enable();
  fpga_program_sram(data, size);
  fpga_disable();
  printf("...done\n");

  usb_close();
  exit(0);
}

static void maint_fpga_program_flash(const char *name)
{
  u8 *data;
  int size = os_file_read_all(name, &data);

  printf("Programming FPGA flash\n");
  usb_init();
  open_capture_device();
  fpga_enable();
  fpga_program_flash(data, size);
  fpga_disable();
  printf("...done\n");

  usb_close();
  exit(0);
}

static void maint_fpga_erase(void)
{
  printf("Erasing FPGA flash\n");
  usb_init();
  open_capture_device();
  fpga_enable();
  fpga_erase_flash();
  fpga_disable();
  printf("... done\n");

  usb_close();
  exit(0);
}

static void maint_speed_test(void)
{
  usb_init();
  log_print("Starting speed test");
  open_capture_device();
  usb_speed_test();
  usb_close();
  exit(0);
}

//-----------------------------------------------------------------------------
// Capture dispatch: pick the engine by interface name or by probing the bus.

static void missing_device_error(device_kind probe)
{
  if (probe == Device_None)
    os_error("no capture device found (gen1 1209:6688 rev 0x0001 / 6666:6620, gen2 1209:6688 rev 0x0602)");
  if (probe == Device_Fx2lp_Only)
    os_error("only an unconfigured FX2LP (04b4:8613) was found: if this is the gen1 sniffer, "
             "load the firmware first ('--mcu-sram usb_sniffer.bin' to run, or '--mcu-eeprom' "
             "to program it permanently); if it is a different FX2LP device, it is not a "
             "capture device and must be unplugged");
  if (probe == Device_Both)
    os_error("both capture generations are connected; unplug one of them");
}

static int run_selected_capture(const packet_opts *popts)
{
  if (g_opt.replay)
    return run_capture_gen2(popts);   // offline mode is gen2-only

  if (g_opt.extcap_interface && strcmp(g_opt.extcap_interface, INTERFACE_NAME))
    os_error("invalid interface '%s'", g_opt.extcap_interface);

  // The engine is picked by probing the bus (VID/PID + bcdDevice).
  device_kind probe = device_probe();

  if (probe == Device_Gen1)
    return run_capture_gen1();
  if (probe == Device_Gen2)
    return run_capture_gen2(popts);

  missing_device_error(probe);
  return 1;
}

//-----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  os_set_binary_io();        // Windows: keep extcap protocol output clean

#ifndef _WIN32
  static struct sigaction sigact;
  sigact.sa_handler = sig_handler;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigaction(SIGINT, &sigact, NULL);
#else
  // MinGW CRT has no sigaction; plain signal() is enough for the console
  // Ctrl+C path (Wireshark terminates the extcap process on Windows anyway).
  signal(SIGINT, sig_handler);
#endif
  signal(SIGTERM, sig_handler);

  log_open_file(getenv("USB_SNIFFER_LOG"));

  parse_command_line(argc, argv);

  // Live extcap sessions must not write routine logs to stderr: Wireshark
  // reports any extcap stderr output as an error ("Error from extcap pipe").
  // Fatal errors (os_error/os_check) still go through.
  if (g_opt.extcap_capture && g_opt.extcap_fifo)
    log_set_quiet(true);

  if (handle_extcap_request())
    return 0;

  packet_opts popts;
  popts.fold_empty = g_opt.fold_empty;
  popts.exclude_line_state = g_opt.exclude_line_state;
  popts.capture_speed = g_opt.capture_speed;
  popts.capture_trigger = g_opt.capture_trigger;
  popts.capture_limit = g_opt.capture_limit;

  // Offline replay needs no capture flags and no hardware.
  if (g_opt.replay)
    return run_selected_capture(&popts);

  // Live capture first (upstream gen1 precedence: capture wins over the
  // maintenance tools when both are present on the command line).
  if (g_opt.extcap_capture && g_opt.extcap_fifo)
    return run_selected_capture(&popts);

  if (g_opt.test)
    maint_speed_test();
  else if (g_opt.mcu_sram)
    maint_mcu_sram(g_opt.mcu_sram);
  else if (g_opt.mcu_eeprom)
    maint_mcu_eeprom(g_opt.mcu_eeprom);
  else if (g_opt.fpga_sram)
    maint_fpga_program_sram(g_opt.fpga_sram);
  else if (g_opt.fpga_flash)
    maint_fpga_program_flash(g_opt.fpga_flash);
  else if (g_opt.fpga_erase)
    maint_fpga_erase();
  else
  {
    log_print("nothing to do, use '-h' for help");
    return 1;
  }
}