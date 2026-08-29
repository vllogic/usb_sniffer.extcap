// SPDX-License-Identifier: BSD-3-Clause
// Stream layer: takes the raw byte stream of EP1 IN (concatenated UHSIF
// blocks) and carves it into blocks.  Every block is validated, sequence
// numbers are checked, and payload bytes are handed to the frame layer while
// zero-length (ACK) blocks are handed to the command layer.
//
// The stream is assumed to be little-endian with respect to the UHSIF 32-bit
// words, i.e. the low byte of each FPGA word is the first byte on the wire.
// A block header is 4 words and payload is tx_payload_len words:
//
//   w0 = {crc16, 0x6CC6}
//   w1 = {12'b0, channel_mask}
//   w2 = {lut_chk8, capturing, iserdes_clk_div, mode, vco_select,
//         tx_payload_len[11:0]}
//   w3 = {seq[15:0], v_bias_pwm1, v_bias_pwm0}

#ifndef STREAM_H
#define STREAM_H

#include "os_common.h"

// Called with a data block payload (the capture byte stream, may span USB
// packets and may begin/end mid-packet).
typedef void (*stream_data_fn)(void *user, const u8 *data, int size);

// Called once per ACK block received from the FPGA.
typedef void (*stream_ack_fn)(void *user);

// Called when the block framing desynchronizes (invalid header or a sequence
// jump).  The layer immediately starts a resync scan.
typedef void (*stream_rsync_fn)(void *user);

typedef struct
{
  stream_data_fn  data_cb;
  stream_ack_fn   ack_cb;
  stream_rsync_fn rsync_cb;
  void           *user;
} stream_callbacks;

typedef struct stream stream;

stream *stream_new(const stream_callbacks *cb);
void stream_delete(stream *s);

// Feed an arbitrary chunk of the upstream byte stream.
void stream_feed(stream *s, const u8 *data, int size);

#endif // STREAM_H