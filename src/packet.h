// SPDX-License-Identifier: BSD-3-Clause
// Frame + interpret layer.  Consumes the capture byte stream (the payload
// bytes of UHSIF data blocks) and reproduces the upstream usb-sniffer
// capture behavior:
//
//   - variable-length packet slicing (7-byte data headers / 4-byte status
//     headers, 20-bit 60 MHz timestamps converted to ns)
//   - error flag extraction and protocol desync detection
//   - event synthesis (line state, keep-alive, VBUS, trigger, speed),
//   - empty-frame folding, capture gating on trigger and overflow reports
//
// Everything is written out through a pcapng writer.

#ifndef PACKET_H
#define PACKET_H

#include "os_common.h"
#include "pcapng.h"

typedef struct
{
  bool  fold_empty;          // fold SOF/IN/NAK/keep-alive frames
  bool  exclude_line_state;  // do not emit line state events
  int   capture_speed;       // CaptureSpeed_LS/FS/HS/Reset
  int   capture_trigger;     // CaptureTrigger_Disabled/Low/High/Falling/Rising
  s64   capture_limit;       // packet count limit, -1 for unlimited
} packet_opts;

typedef struct packet packet;

packet *packet_new(const packet_opts *opts, pcapng *out);

// (Re)initialize the parser state at the start of a capture.
void packet_start(packet *p);

// Write the capture-start announcement ("Starting capture" / "Waiting for a
// trigger") and enable the capture gate.  Call after pcapng_begin().
void packet_announce(packet *p);

// Feed raw capture bytes (the concatenated UHSIF data block payloads).
void packet_feed(packet *p, const u8 *data, int size);

// Report a stream-level desynchronization / link packet loss.
void packet_rsync(packet *p);

// True once the capture must stop (desync, capture limit).
bool packet_finished(const packet *p);

void packet_delete(packet *p);

#endif // PACKET_H