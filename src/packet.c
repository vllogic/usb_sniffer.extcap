// SPDX-License-Identifier: BSD-3-Clause

// This file is a faithful port of the capture/interpret logic from the
// upstream usb-sniffer project (software/capture.c), adapted to the UHSIF
// pipeline (packet_feed() is invoked with UHSIF data block payloads instead
// of raw libusb transfer buffers).

#include "packet.h"
#include "capture_defs.h"

#define TIME_US                        1000
#define TIME_MS                        (1000 * TIME_US)

#define UPDATE_INTERVAL                (2000 * TIME_MS)

#define DATA_HEADER_SIZE               7
#define STATUS_HEADER_SIZE             4
#define DATA_BUF_SIZE                  2048
#define FOLD_BUF_SIZE                  256
#define MAX_DATA_SIZE                  1280

// Byte 0
#define HEADER_STATUS                  0x80
#define HEADER_TOGGLE                  0x40
#define HEADER_ZERO                    0x20
#define HEADER_TS_OVERFLOW             0x10

// Byte 3 in data frames
#define HEADER_OVERFLOW                0x08
#define HEADER_CRC_ERROR               0x10
#define HEADER_DATA_ERROR              0x20

// Byte 3 in status frames
#define HEADER_LS_OFFS                 0
#define HEADER_LS_MASK                 0x0f
#define HEADER_VBUS                    0x10
#define HEADER_TRIGGER                 0x20
#define HEADER_SPEED_OFFS              6
#define HEADER_SPEED_MASK              0x03

#define PID_SOF                        0xa5
#define PID_IN                         0x69
#define PID_NAK                        0x5a

#define FOLD_LIMIT_LS_FS               1000
#define FOLD_LIMIT_HS                  8000

#define MIN_KEEPALIVE_DURATION         1000 // 1 us
#define MAX_KEEPALIVE_DURATION         2000 // 2 us

// J & K states are for Low-Speed mode
#define LS_INVALID                     -1
#define LS_SE0                         0
#define LS_J3                          12

#define LS_DELTA_THRESHOLD             (10 * TIME_MS)

typedef struct
{
  u64      ts;
  int      size;
  u8       data[DATA_BUF_SIZE];
} CaptureFrame;

struct packet
{
  packet_opts opts;
  pcapng    *out;
  bool       done;

  u8         capture_data[DATA_BUF_SIZE];
  int        capture_data_ptr;
  int        capture_size;
  bool       capture_header;
  bool       capture_status;
  int        capture_toggle;
  int        capture_ls;
  int        capture_vbus;
  int        capture_trigger_input;
  int        capture_speed_in;
  bool       capture_enabled;
  u64        capture_ts_int;
  u64        capture_ts;
  u64        capture_last_ts;   // ts of the last EPB/info written (re-arms the 2 s Periodic update)
  bool       capture_overflow;
  bool       capture_crc_error;
  bool       capture_data_error;
  int        capture_duration;

  CaptureFrame capture_fold_buf[FOLD_BUF_SIZE];
  int        capture_fold_buf_ptr;
  int        capture_fold_count;
  int        capture_saved_ls;
  u64        capture_saved_ts;
};

//-----------------------------------------------------------------------------
static void line_state_event(packet *p);
static void keepalive_event(packet *p, u64 ts, int delta);
static void stop_folding(packet *p);

//-----------------------------------------------------------------------------
static void capture_info(packet *p, u64 ts, const char *fmt, ...)
{
  char str[512];
  va_list args;

  va_start(args, fmt);
  int len = vsnprintf(str, sizeof(str), fmt, args);
  va_end(args);

  line_state_event(p);
  stop_folding(p);

  pcapng_write_info(p->out, ts, str, len);
  p->capture_last_ts = ts;

  pcapng_flush(p->out);
}

//-----------------------------------------------------------------------------
// Write a data EPB and re-arm the Periodic-update timer, mirroring the
// original capture.c write_packet(): every written block/info refreshes
// capture_last_ts so timeout_event() only fires after 2 s of silence.
static void write_packet(packet *p, u64 ts, const u8 *data, int size)
{
  pcapng_write_epb(p->out, ts, data, size);
  p->capture_last_ts = ts;
}

//-----------------------------------------------------------------------------
static void write_keepalive(packet *p, u64 ts)
{
  capture_info(p, ts, "Keep-alive");
}

//-----------------------------------------------------------------------------
static void timeout_event(packet *p)
{
  if (p->capture_enabled)
    capture_info(p, p->capture_ts, "Periodic update");
}

//-----------------------------------------------------------------------------
static void line_state_event(packet *p)
{
  int dp = (p->capture_saved_ls >> 0) & 3;
  int dm = (p->capture_saved_ls >> 2) & 3;
  int delta = (int)(p->capture_ts - p->capture_saved_ts);
  char str[256];

  if (LS_INVALID == p->capture_saved_ls)
    return;

  p->capture_saved_ls = LS_INVALID;

  if (p->opts.exclude_line_state)
    return;

  sprintf(str, "Line state: ");

  if (dp == 0 && dm == 0)
  {
    strcat(str, "SE0");
  }
  else if (dp == 0)
  {
    strcat(str, (CaptureSpeed_LS == p->capture_speed_in) ? "J" : "K");
  }
  else if (dm == 0)
  {
    strcat(str, (CaptureSpeed_LS == p->capture_speed_in) ? "K" : "J");
  }
  else
  {
    char buf[64];
    snprintf(buf, sizeof(buf), "Undefined (DP=%d / DM=%d)", dp, dm);
    strcat(str, buf);
  }

  if (delta < LS_DELTA_THRESHOLD)
  {
    char buf[64];

    if (delta < TIME_US)
      snprintf(buf, sizeof(buf), " (%.2f ns)", (float)delta);
    else if (delta < TIME_MS)
      snprintf(buf, sizeof(buf), " (%.2f us)", (float)delta / TIME_US);
    else
      snprintf(buf, sizeof(buf), " (%.2f ms)", (float)delta / TIME_MS);

    strcat(str, buf);
  }

  capture_info(p, p->capture_saved_ts, str);
}

//-----------------------------------------------------------------------------
static void status_event(packet *p, int ls, int vbus, int trigger, int speed)
{
  if (p->capture_trigger_input != trigger)
  {
    bool was_enabled = p->capture_enabled;

    if (CaptureTrigger_Disabled == p->opts.capture_trigger)
      p->capture_enabled = true;
    else if (CaptureTrigger_Low == p->opts.capture_trigger)
      p->capture_enabled = (trigger == 0);
    else if (CaptureTrigger_High == p->opts.capture_trigger)
      p->capture_enabled = (trigger == 1);
    else if (CaptureTrigger_Falling == p->opts.capture_trigger)
      p->capture_enabled = p->capture_enabled || (trigger == 0 && p->capture_trigger_input == 1);
    else if (CaptureTrigger_Rising == p->opts.capture_trigger)
      p->capture_enabled = p->capture_enabled || (trigger == 1 && p->capture_trigger_input == 0);
    else
      os_assert(false);

    p->capture_trigger_input = trigger;

    capture_info(p, p->capture_ts, "Trigger input = %d", p->capture_trigger_input);

    if (p->capture_enabled && !was_enabled)
      capture_info(p, p->capture_ts, "Starting capture");
    else if (was_enabled && !p->capture_enabled)
      capture_info(p, p->capture_ts, "Waiting for a trigger");
  }

  if (p->capture_vbus != vbus)
  {
    p->capture_vbus = vbus;
    capture_info(p, p->capture_ts, "VBUS %s", p->capture_vbus ? "ON" : "OFF");
  }

  if (p->capture_speed_in != speed)
  {
    static const char *str[] = { "Low-Speed", "Full-Speed", "High-Speed", "" };
    p->capture_speed_in = speed;

    if (p->capture_enabled)
    {
      if (CaptureSpeed_Reset == speed)
        capture_info(p, p->capture_ts, "--- Bus Reset ---");
      else
        capture_info(p, p->capture_ts, "Detected speed: %s", str[p->capture_speed_in]);
    }
  }

  if (p->capture_ls != ls)
  {
    u64 delta = p->capture_ts - p->capture_saved_ts;
    bool handle = true;

    p->capture_ls = ls;

    if (CaptureSpeed_LS == p->capture_speed_in && LS_SE0 == p->capture_saved_ls && LS_J3 == ls &&
        (MIN_KEEPALIVE_DURATION < (int)delta && (int)delta < MAX_KEEPALIVE_DURATION))
    {
      p->capture_saved_ls = LS_INVALID;
      keepalive_event(p, p->capture_saved_ts, (int)delta);
      handle = false;
    }

    if (handle)
    {
      line_state_event(p);
      p->capture_saved_ls = ls;
      p->capture_saved_ts = p->capture_ts;
    }
  }
}

//-----------------------------------------------------------------------------
static void stop_folding(packet *p)
{
  int count = p->capture_fold_count;
  int ptr   = p->capture_fold_buf_ptr;

  if (0 == count && 0 == ptr)
    return;

  p->capture_fold_count = 0;
  p->capture_fold_buf_ptr = 0;

  if (count == 1)
    capture_info(p, p->capture_ts, "Folded empty frame");
  else if (count > 1)
    capture_info(p, p->capture_ts, "Folded %d empty frames", count);

  for (int i = 0; i < ptr; i++)
  {
    if (p->capture_fold_buf[i].size < 0)
      write_keepalive(p, p->capture_fold_buf[i].ts);
    else
      write_packet(p, p->capture_fold_buf[i].ts, p->capture_fold_buf[i].data, p->capture_fold_buf[i].size);
  }
}

//-----------------------------------------------------------------------------
static void fold_packet(packet *p, u64 ts, u8 *data, int size)
{
  p->capture_fold_buf[p->capture_fold_buf_ptr].ts = ts;
  p->capture_fold_buf[p->capture_fold_buf_ptr].size = size;
  memcpy(p->capture_fold_buf[p->capture_fold_buf_ptr].data, data, (size_t)size);
  p->capture_fold_buf_ptr++;
}

//-----------------------------------------------------------------------------
static void fold_keepalive(packet *p, u64 ts, int delta)
{
  p->capture_fold_buf[p->capture_fold_buf_ptr].ts = ts;
  p->capture_fold_buf[p->capture_fold_buf_ptr].size = -delta;
  p->capture_fold_buf_ptr++;
}

//-----------------------------------------------------------------------------
static void check_capture_limit(packet *p)
{
  p->opts.capture_limit--;

  if (p->opts.capture_limit == 0)
  {
    capture_info(p, p->capture_ts, "Capture limit reached");
    p->done = true;
  }
}

//-----------------------------------------------------------------------------
static void keepalive_event(packet *p, u64 ts, int delta)
{
  if (!p->capture_enabled)
    return;

  if (!p->opts.fold_empty)
  {
    write_keepalive(p, ts);
  }
  else if (p->capture_fold_buf_ptr)
  {
    p->capture_fold_count++;
    p->capture_fold_buf_ptr = 0;

    if (p->capture_fold_count == FOLD_LIMIT_LS_FS)
      stop_folding(p);

    fold_keepalive(p, ts, delta);
  }
  else
  {
    fold_keepalive(p, ts, delta);
  }

  check_capture_limit(p);
}

//-----------------------------------------------------------------------------
static void data_event(packet *p)
{
  bool data_error = p->capture_crc_error || p->capture_data_error;
  bool allow_sof  = (CaptureSpeed_LS != p->capture_speed_in);
  int  pid = p->capture_data[0];

  if (!p->capture_enabled)
    return;

  line_state_event(p);

  if (p->capture_overflow || data_error || FOLD_BUF_SIZE == p->capture_fold_buf_ptr)
    stop_folding(p);

  if (p->capture_overflow)
    capture_info(p, p->capture_ts, "Hardware buffer overflow");

  if (p->capture_data_error)
    capture_info(p, p->capture_ts, "USB PHY error");

  if (data_error || !p->opts.fold_empty)
  {
    write_packet(p, p->capture_ts, p->capture_data, p->capture_size);
  }
  else if (p->capture_fold_buf_ptr)
  {
    if (PID_IN == pid || PID_NAK == pid)
    {
      fold_packet(p, p->capture_ts, p->capture_data, p->capture_size);
    }
    else if (PID_SOF == pid && allow_sof)
    {
      p->capture_fold_count++;
      p->capture_fold_buf_ptr = 0;

      if (p->capture_fold_count == ((CaptureSpeed_HS == p->capture_speed_in) ? FOLD_LIMIT_HS : FOLD_LIMIT_LS_FS))
        stop_folding(p);

      fold_packet(p, p->capture_ts, p->capture_data, p->capture_size);
    }
    else
    {
      stop_folding(p);
      write_packet(p, p->capture_ts, p->capture_data, p->capture_size);
    }
  }
  else
  {
    if (PID_SOF == pid && allow_sof)
      fold_packet(p, p->capture_ts, p->capture_data, p->capture_size);
    else
      write_packet(p, p->capture_ts, p->capture_data, p->capture_size);
  }

  check_capture_limit(p);
}

//-----------------------------------------------------------------------------
static void desync_error(packet *p)
{
  // v2 semantics: report the loss and re-synchronize the frame walk instead
  // of stopping the capture.  Transitional bus states (speed re-detect,
  // line-state glitches, overflow-shortened frames) can corrupt a single
  // frame; the stream layer already resyncs at block level and the session
  // must survive those events.
  capture_info(p, p->capture_ts, "Error: frame desynchronization, resynchronizing");

  char header[256] = {0};

  for (int i = 0; i < p->capture_size; i++)
  {
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%02x ", p->capture_data[i]);
    strcat(header, tmp);
  }

  capture_info(p, p->capture_ts, "Packet header: %s", header);

  // Reset the frame assembler; the next header starts a fresh walk.
  p->capture_size = 0;
  p->capture_data_ptr = 0;
  p->capture_header = true;
  p->capture_status = false;
}

//-----------------------------------------------------------------------------
static void check_header(packet *p, int toggle, int zero)
{
  if (toggle == p->capture_toggle && 0 == zero)
    return;

  if (toggle != p->capture_toggle)
    capture_info(p, p->capture_ts, "Error: received toggle value %d, expected %d", toggle, p->capture_toggle);

  if (zero)
    capture_info(p, p->capture_ts, "Error: zero bit in the header is not zero");

  desync_error(p);
}

//-----------------------------------------------------------------------------
static void check_data_size(packet *p, int size)
{
  if (DATA_HEADER_SIZE <= size && size <= MAX_DATA_SIZE)
    return;

  capture_info(p, p->capture_ts, "Error: invalid data size (%d)", size);
  desync_error(p);
}

//-----------------------------------------------------------------------------
static inline void capture_sm(packet *p, u8 byte)
{
  if (p->capture_header && 0 == p->capture_data_ptr)
  {
    p->capture_status = (0 == (byte & HEADER_STATUS));
    p->capture_size = p->capture_status ? STATUS_HEADER_SIZE : DATA_HEADER_SIZE;
  }

  p->capture_data[p->capture_data_ptr++] = byte;

  if (p->capture_data_ptr < p->capture_size)
    return;

  if (p->capture_header)
  {
    int ts     = ((p->capture_data[0] & 0xf) << 16) | (p->capture_data[1] << 8) | p->capture_data[2];
    int toggle = (p->capture_data[0] & HEADER_TOGGLE) ? 1 : 0;
    int zero   = (p->capture_data[0] & HEADER_ZERO) ? 1 : 0;

    check_header(p, toggle, zero);

    if (p->capture_data[0] & HEADER_TS_OVERFLOW)
      p->capture_ts_int += 0x100000;

    p->capture_ts = ((p->capture_ts_int | ts) * 100) / 6; // convert to ns
    p->capture_toggle = 1 - toggle;

    // Signed comparison: a frame whose ts regresses (e.g. a burst of
    // overflow-marker status frames or a tool-generated stream) must never
    // look like a 2 s gap -- with unsigned arithmetic the negative delta
    // wraps to a huge positive value and spuriously fires the update.
    if ((s64)(p->capture_ts - p->capture_last_ts) > (s64)UPDATE_INTERVAL)
      timeout_event(p);

    if (p->capture_status)
    {
      int ls      = (p->capture_data[3] >> HEADER_LS_OFFS) & HEADER_LS_MASK;
      int vbus    = (p->capture_data[3] & HEADER_VBUS) ? 1 : 0;
      int trigger = (p->capture_data[3] & HEADER_TRIGGER) ? 1 : 0;
      int speed   = (p->capture_data[3] >> HEADER_SPEED_OFFS) & HEADER_SPEED_MASK;

      status_event(p, ls, vbus, trigger, speed);
    }
    else // data
    {
      int size = (((int)p->capture_data[3] & 0x7) << 8) | p->capture_data[4];

      check_data_size(p, size);

      p->capture_size = size - DATA_HEADER_SIZE;
      p->capture_overflow = (p->capture_data[3] & HEADER_OVERFLOW) ? true : false;
      p->capture_crc_error = (p->capture_data[3] & HEADER_CRC_ERROR) ? true : false;
      p->capture_data_error = (p->capture_data[3] & HEADER_DATA_ERROR) ? true : false;
      p->capture_duration = ((int)p->capture_data[5] << 8) | p->capture_data[6];
      p->capture_header = (0 == p->capture_size);
    }
  }
  else // payload
  {
    p->capture_header = true;
    data_event(p);
  }

  p->capture_data_ptr = 0;
}

//-----------------------------------------------------------------------------
packet *packet_new(const packet_opts *opts, pcapng *out)
{
  packet *p = os_alloc(sizeof(packet));

  p->opts = *opts;
  p->out = out;

  packet_start(p);

  return p;
}

//-----------------------------------------------------------------------------
void packet_start(packet *p)
{
  p->done = false;
  p->capture_data_ptr = 0;
  p->capture_size = 0;
  p->capture_header = true;
  p->capture_status = false;
  p->capture_toggle = 0;
  p->capture_ls = -1;
  p->capture_vbus = -1;
  p->capture_trigger_input = -1;
  p->capture_speed_in = -1;
  p->capture_enabled = false;
  p->capture_ts_int = 0;
  p->capture_ts = 0;
  p->capture_last_ts = 0;
  p->capture_overflow = false;
  p->capture_crc_error = false;
  p->capture_data_error = false;
  p->capture_duration = 0;
  p->capture_fold_buf_ptr = 0;
  p->capture_fold_count = 0;
  p->capture_saved_ls = LS_INVALID;
  p->capture_saved_ts = 0;
}

//-----------------------------------------------------------------------------
void packet_announce(packet *p)
{
  // FPGA init may feed the parser stale pre-session blocks whose frame
  // toggle phase does not match the fresh session baseline, tripping a
  // (benign) desync that would kill the capture before it starts.  Re-arm
  // the session here; the toggle tracker keeps its last-seen phase, which
  // is correct for a continuous alternating frame stream.
  p->done = false;

  if (CaptureTrigger_Disabled == p->opts.capture_trigger)
  {
    capture_info(p, 0, "Starting capture");
    p->capture_enabled = true;
  }
  else
    capture_info(p, p->capture_ts, "Waiting for a trigger");

  pcapng_flush(p->out);
}

//-----------------------------------------------------------------------------
void packet_feed(packet *p, const u8 *data, int size)
{
  if (p->done)
    return;

  for (int i = 0; i < size; i++)
  {
    capture_sm(p, data[i]);

    if (p->done)
      return;
  }
}

//-----------------------------------------------------------------------------
void packet_rsync(packet *p)
{
  capture_info(p, p->capture_ts, "Error: USB link packet loss, resynchronized");
}

//-----------------------------------------------------------------------------
bool packet_finished(const packet *p)
{
  return p->done;
}

//-----------------------------------------------------------------------------
void packet_delete(packet *p)
{
  os_free(p);
}