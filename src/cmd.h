// SPDX-License-Identifier: BSD-3-Clause
// Command layer: serial PC->FPGA control plane.  Commands are 16-byte
// (4 x u32 LE) packets sent on EP1 OUT:
//
//   w0 = {crc16, 0xC7F3}
//   w1 = {seq[15:8], cmd_id[7:0]}
//   w2 = param
//   w3 = {20'b0, payload_len[11:0]}   (always 0; no attached data stream)
//
// The model is strictly serial: send one command, wait for the FPGA ACK
// block (16-byte zero-length block observed on EP1 IN), retry on timeout.

#ifndef CMD_H
#define CMD_H

#include "os_common.h"

typedef struct transport transport;

typedef struct
{
  transport *tr;
  u8         seq;         // command sequence counter (w1[15:8])
  bool       waiting;     // an ACK is expected for the current command
  bool       ack_seen;    // set by the stream layer when an ACK arrives
  bool       fatal;
  bool       suppress;    // drop upstream data until the first command is sent
} cmd;

void cmd_init(cmd *c, transport *tr);

// True while the transport is still draining stale data from before the
// first command was sent (upstream data during this phase is discarded).
bool cmd_input_suppressed(const cmd *c);

// The stream layer calls this every time an ACK block is received.
void cmd_ack_event(cmd *c);

// Send one command and wait for its ACK.  Returns true once the FPGA
// acknowledged the command (an ACK observed after the send resolves it,
// even if a retry was in progress).  Returns false on persistent failure.
bool cmd_exec(cmd *c, int id, u32 param);

// Fire-and-forget command: transmit without waiting for the ACK and without
// touching the sequence / suppress state.  Used only by the pre-session
// cleanup phase (Enable 0 / Reset 1), whose ACKs are drained away by
// transport_discard() together with the stale upstream data.
void cmd_tx_quiet(cmd *c, int id, u32 param);

#endif // CMD_H