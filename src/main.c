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
// Device-side callbacks (all run in the transport event loop).
typedef struct
{
  stream *stream;
  cmd    *cmd;
  packet *packet;
} context;

static void feed_cb(void *user, const u8 *data, int size)
{
  context *cx = (context *)user;
  stream_feed(cx->stream, data, size);
}

static void data_cb(void *user, const u8 *data, int size)
{
  context *cx = (context *)user;

  if (!cmd_input_suppressed(cx->cmd))
    packet_feed(cx->packet, data, size);
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
static void capture_init_cmds(cmd *c, int speed)
{
  // Serialized init sequence mirroring the upstream plugin, mapped onto the
  // UHSIF command set.  The FPGA acknowledges every command with a 16-byte
  // ACK block before the next one is issued.  Runs only after the stale data
  // flush, so the upstream stream is clean and every ACK resolves promptly.
  struct { int id; u32 param; } init[] =
  {
    { UHSIF_CMD_SPEED,  (u32)speed }, // Speed (0=LS 1=FS 2=HS 3=AUTO)
    { UHSIF_CMD_RESET,  0 },          // Reset 0
    { UHSIF_CMD_ENABLE, 1 },          // Enable 1
  };

  for (unsigned i = 0; i < ARRAY_SIZE(init); i++)
  {
    if (!cmd_exec(c, init[i].id, init[i].param))
      os_error("FPGA did not acknowledge command 0x%02x, aborting", init[i].id);

    log_print("cmd: 0x%02x(%u) acknowledged", init[i].id, (unsigned)init[i].param);
  }
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
  capture_stop_and_flush(&cmd, tr);
  capture_init_cmds(&cmd, popts->capture_speed);

  // Now that the FPGA is enabled, lay down the pcapng skeleton and flush any
  // buffered pre-session blocks, then enable the capture gate.
  pcapng_begin(out, dlt_for_speed(popts->capture_speed));
  packet_announce(packet);

  transport_stream_mode(tr);

  log_print("capture running");

  // Main event loop.
  while (!g_stop && transport_alive(tr) && !packet_finished(packet))
  {
    if (!transport_events(tr, 200))
      break;
  }

  log_print("capture finished");

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