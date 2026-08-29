// SPDX-License-Identifier: BSD-3-Clause
// Transport abstraction.  Two backends exist (see transport.c):
//
//   - libusb:   real CH32H417 device, EP1 IN async bulk read + EP1 OUT async
//               bulk write (docs/protocol.md).
//   - replay:   a binary file containing the pre-recorded upstream byte
//               stream (UHSIF blocks + ACKs) used for offline verification.
//
// The upstream byte stream is delivered to the device-independent pipeline
// through a feed callback.  transport_events() pumps the event loop: for
// libusb it runs libusb_handle_events() and for replay it reads the next
// chunk from the file.  It returns false when no more events can ever
// happen (replay EOF or a fatal device error).

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "os_common.h"

// Called with raw upstream bytes as they arrive from EP1 IN.
typedef void (*transport_feed_fn)(void *user, const u8 *data, int size);

typedef struct
{
  transport_feed_fn feed;
  void             *feed_user;
} transport_callbacks;

typedef struct transport transport;

typedef struct
{
  bool (*open)(transport *t);
  void (*discard)(transport *t);
  void (*stream_mode)(transport *t);
  bool (*events)(transport *t, long timeout_ms);
  int  (*write)(transport *t, const u8 *data, int size);
  bool (*alive)(const transport *t);
  void (*close)(transport *t);
} transport_ops;

// libusb: open/claim the device (VID 0x1209 / PID 0x6688).  The EP1 IN async
// transfers are NOT started until stream_mode() so the pre-session cleanup
// (quiet commands + transport_discard()) runs without upstream data entering
// the pipeline; during the command phase transport_events() reads EP1 IN
// synchronously to resolve command ACKs.  replay: open the stream file.
transport *transport_libusb_new(const transport_callbacks *cb);
transport *transport_replay_new(const transport_callbacks *cb, const char *path);

bool transport_open(transport *t);

// Synchronously drain and discard whatever the upstream endpoint still holds
// (stale blocks left over from a previous session killed mid-capture).  This
// mirrors the reference plugin's usb_flush_data() and must run while the FPGA
// is stopped (Enable 0 / Reset 1), before the first acknowledged command.
// No-op for replay.
void transport_discard(transport *t);

// Switch the transport to the streaming phase.  For libusb this starts the
// EP1 IN async pool (until then the command-phase synchronous reads resolve
// ACKs); for replay it switches from 16-byte ACK reads to larger data reads.
void transport_stream_mode(transport *t);

// Pump events for up to timeout_ms.  Returns false when the session ended
// (replay EOF, fatal error or device disconnect).
bool transport_events(transport *t, long timeout_ms);

// Submit a packet (EP1 OUT command) to the device.  Returns 0 on success.
int transport_write(transport *t, const u8 *data, int size);

// True while the transport can still produce or consume data.
bool transport_alive(const transport *t);

void transport_close(transport *t);

#endif // TRANSPORT_H