// SPDX-License-Identifier: BSD-3-Clause
// UHSIF 4-word protocol constants shared by the command (PC->FPGA) and
// stream (FPGA->PC) layers.  See docs/protocol.md for field-level details.

#ifndef UHSIF_H
#define UHSIF_H

#include "os_common.h"

// w0 low half-word magic values (the high half-word carries crc16).
// 0x5AA5 was retired in v2.2: it is a common test-pattern value, so payload
// data regularly produced scan candidates; 0xC7F3 is deliberately cold
// (both wire bytes non-ASCII, not a standard test vector, ~7 bits from 6CC6).
#define UHSIF_CMD_MAGIC16  0xC7F3u   // w0[15:0] of a PC->FPGA command packet
#define UHSIF_BLK_MAGIC16  0x6CC6u   // w0[15:0] of an FPGA->PC block header

// Command IDs (request / req_buf[1] byte0).  The FPGA maps these to the
// capture control register bits: RESET->bit0, ENABLE->bit1, SPEED->bits2:3,
// TEST->bit4.
#define UHSIF_CMD_RESET        0x01
#define UHSIF_CMD_ENABLE       0x02
#define UHSIF_CMD_SPEED        0x03
#define UHSIF_CMD_TEST         0x04

// Reserved for later use.
#define UHSIF_CMD_UPLOAD_PARAMS 0x20
#define UHSIF_CMD_CHANNEL_MASK  0x21

// Block framing.
#define UHSIF_HEADER_WORDS       4
#define UHSIF_ACK_SIZE           (UHSIF_HEADER_WORDS * 4)             // 16 bytes, no payload
// usb_sniffer2: data blocks may be ANY length 1..4092 words.  The v1
// (logic-analyzer) minimum of 120 was only needed there to keep every block
// self-parseable; the sniffer streams a continuous byte stream, so the FPGA
// uploads whatever is available (low-rate packets are flushed by a 10 ms
// timeout), no minimum is enforced.
#define UHSIF_MIN_PAYLOAD_WORDS  1
#define UHSIF_MAX_PAYLOAD_WORDS  4092
#define UHSIF_BLK_MAX_SIZE       (4 * (UHSIF_HEADER_WORDS + UHSIF_MAX_PAYLOAD_WORDS))

// Command handshake timing (serial model).
#define UHSIF_CMD_TIMEOUT_MS     200
#define UHSIF_CMD_RETRIES        3

// Header checksum: CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB-first
// per byte, no reflection, no final XOR) over the 12 header bytes in wire
// order (w1, w2, w3, each little-endian).  Placed into the high half-word of
// a packet's w0 (both directions, symmetric).  Replaces the v2.1 fold-XOR,
// which missed symmetric double-bit errors; the CRC detects all bursts
// <= 16 bits, all odd-bit errors and the double-bit errors the fold missed.
static inline u16 uhsif_hdr_crc16(u32 w1, u32 w2, u32 w3)
{
  u16 crc = 0xFFFFu;

  for (int i = 0; i < 12; i++)
  {
    u32 w = (i < 4) ? w1 : (i < 8) ? w2 : w3;

    crc ^= (u16)((w >> ((i & 3) * 8)) & 0xffu) << 8;
    for (int b = 0; b < 8; b++)
      crc = (u16)((crc & 0x8000u) ? (u16)((crc << 1) ^ 0x1021u) : (crc << 1));
  }
  return crc;
}

// Upstream block header validity: magic half-word plus checksum match.
static inline bool uhsif_blk_hdr_ok(u32 w0, u32 w1, u32 w2, u32 w3)
{
  return (u16)w0 == UHSIF_BLK_MAGIC16 && (w0 >> 16) == uhsif_hdr_crc16(w1, w2, w3);
}

// Command packet layout: 16 bytes = 4 x u32 LE.
//   w0 = {crc16(w1, w2, w3), UHSIF_CMD_MAGIC16}
//   w1 = {16'b0, cmd_seq[15:8], cmd_id[7:0]}
//   w2 = param
//   w3 = {20'b0, payload_len[11:0]} (always 0; no attached data stream)
#define UHSIF_CMD_SIZE           16

// Upstream block header layout (v2):
//   w0 = {crc16(w1, w2, w3), UHSIF_BLK_MAGIC16}
//   w1 = {20'b0, channel_mask[11:0]}          bit0 = ULPI capture channel
//   w2 = {12'b0, test, capturing, speed[1:0], 11'b0, VER[4:0]}, VER = 2
//   w3 = {seq[7:0], payload_len[11:0], hdr3[11:0]=0}
static inline u32 uhsif_le32(const u8 *p)
{
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline void uhsif_put_le32(u8 *p, u32 v)
{
  p[0] = (u8)v;
  p[1] = (u8)(v >> 8);
  p[2] = (u8)(v >> 16);
  p[3] = (u8)(v >> 24);
}

// payload_len lives in w3[23:12] (number of 32-bit payload words).
static inline u32 uhsif_blk_payload_len(const u8 *hdr)
{
  return (uhsif_le32(hdr + 12) >> 12) & 0xfffu;
}

// Block sequence number lives in w3[31:24]; incremented by the FPGA for
// every transmitted block (ACK and data blocks share the counter).
static inline u8 uhsif_blk_seq(const u8 *hdr)
{
  return (u8)(uhsif_le32(hdr + 12) >> 24);
}

static inline int uhsif_blk_is_ack(const u8 *hdr)
{
  return uhsif_blk_payload_len(hdr) == 0;
}

static inline int uhsif_blk_size(const u8 *hdr)
{
  return UHSIF_ACK_SIZE + 4 * (int)uhsif_blk_payload_len(hdr);
}

#endif // UHSIF_H