// SPDX-License-Identifier: BSD-3-Clause
// Replay transport backend: a binary file containing the pre-recorded
// upstream byte stream (UHSIF blocks).  Used for offline verification of the
// full capture pipeline without any hardware.
//
// The file layout is produced by tools/make_fake_stream.py:
//
//   [ ACK blocks x N ] [ data blocks x M ]
//
// The backend has two phases.  During the command phase each
// transport_events() call delivers exactly one 16-byte ACK block, so the
// command layer observes its ACKs in order.  transport_stream_mode()
// switches to the data phase where larger chunks are delivered.

#include "transport.h"
#include "transport_internal.h"
#include <unistd.h>
#include <fcntl.h>

#ifdef _WIN32
// MinGW CRT text mode would stop read() at the first 0x1A byte.
#define REPLAY_OPEN_FLAGS (O_RDONLY | O_BINARY)
#else
#define REPLAY_OPEN_FLAGS  O_RDONLY
#endif

#define DATA_CHUNK  4096

typedef struct
{
  int  fd;
  bool alive;
  bool stream_mode;
  u8   chunk[DATA_CHUNK];
} replay_priv;

//-----------------------------------------------------------------------------
static bool tr_open(transport *t)
{
  replay_priv *p = (replay_priv *)t->priv;

  p->alive = true;

  return true;
}

//-----------------------------------------------------------------------------
static void tr_discard(transport *t)
{
  // Mirror the libusb path: two quiet pre-session commands (Enable 0 /
  // Reset 1) produce two 16-byte ACKs that the live transport drains away.
  // Skip the same two ACKs from the replay file so the acknowledged command
  // phase stays 1:1 (file layout: ACK_COUNT = 2 quiet + 3 handshake).
  replay_priv *p = (replay_priv *)t->priv;

  for (int i = 0; i < 2; i++)
  {
    ssize_t res = read(p->fd, p->chunk, 16);

    if (res < 16)
    {
      // File too short for the expected quiet-command ACKs: stop the replay.
      p->alive = false;
      break;
    }
  }
}

//-----------------------------------------------------------------------------
static void tr_stream_mode(transport *t)
{
  replay_priv *p = (replay_priv *)t->priv;

  p->stream_mode = true;
}

//-----------------------------------------------------------------------------
static bool tr_events(transport *t, long timeout_ms)
{
  replay_priv *p = (replay_priv *)t->priv;

  (void)timeout_ms;

  if (!p->alive)
    return false;

  // Command phase: deliver 16 bytes (one ACK block) per pump.
  int want = p->stream_mode ? DATA_CHUNK : 16;

  ssize_t res = read(p->fd, p->chunk, (size_t)want);

  if (res <= 0)
  {
    p->alive = false;
    return false;
  }

  if (t->cb.feed)
    t->cb.feed(t->cb.feed_user, p->chunk, (int)res);

  if (res < want)
    p->alive = false;

  return true;
}

//-----------------------------------------------------------------------------
static int tr_write(transport *t, const u8 *data, int size)
{
  // The replay transport has no real device to send to; the ACKs in the
  // stream file stand for the FPGA's responses.
  (void)t;
  (void)data;
  (void)size;
  return 0;
}

//-----------------------------------------------------------------------------
static bool tr_alive(const transport *t)
{
  replay_priv *p = (replay_priv *)t->priv;
  return p->alive;
}

//-----------------------------------------------------------------------------
static void tr_close(transport *t)
{
  replay_priv *p = (replay_priv *)t->priv;

  if (p->fd >= 0)
    close(p->fd);

  os_free(p);
}

//-----------------------------------------------------------------------------
transport *transport_replay_new(const transport_callbacks *cb, const char *path)
{
  transport *t = os_alloc(sizeof(transport));
  static const transport_ops ops =
  {
    .open = tr_open,
    .discard = tr_discard,
    .stream_mode = tr_stream_mode,
    .events = tr_events,
    .write = tr_write,
    .alive = tr_alive,
    .close = tr_close,
  };
  replay_priv *p = os_alloc(sizeof(replay_priv));

  p->fd = open(path, REPLAY_OPEN_FLAGS);
  os_check(p->fd >= 0, "could not open replay stream '%s': %s", path, strerror(errno));

  t->cb = *cb;
  t->priv = p;
  t->ops = (transport_ops *)&ops;

  return t;
}