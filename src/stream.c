// SPDX-License-Identifier: BSD-3-Clause

#include "stream.h"
#include "uhsif.h"

#define STREAM_BUF_SIZE  262144              // 256 KiB staging buffer
#define SCAN_KEEP_TAIL   3                   // keep up to 3 bytes across chunks

enum
{
  STREAM_SCAN = 0,       // looking for the next block header magic
  STREAM_BLOCK = 1,      // aligned: next header expected at buf head
};

struct stream
{
  stream_callbacks cb;

  u8   *buf;             // linear staging buffer
  int   cap;
  int   head;            // offset of first unprocessed byte
  int   len;             // number of unprocessed bytes (head..head+len)
  int   state;

  u8    last_seq;        // sequence of the previous block (8-bit, wraps)
  bool  have_seq;        // set after the first accepted block
  int   good;            // consecutive good blocks since the last resync
};

//-----------------------------------------------------------------------------
stream *stream_new(const stream_callbacks *cb)
{
  stream *s = os_alloc(sizeof(stream));

  s->cb = *cb;
  s->buf = os_alloc(STREAM_BUF_SIZE);
  s->cap = STREAM_BUF_SIZE;

  return s;
}

//-----------------------------------------------------------------------------
void stream_delete(stream *s)
{
  os_free(s->buf);
  os_free(s);
}

//-----------------------------------------------------------------------------
static void compact(stream *s)
{
  if (s->head > 0)
  {
    memmove(s->buf, &s->buf[s->head], (size_t)s->len);
    s->head = 0;
  }
}

//-----------------------------------------------------------------------------
static u8 *buf_at(stream *s, int off)
{
  return &s->buf[s->head + off];
}

//-----------------------------------------------------------------------------
static bool header_valid(stream *s, const u8 *hdr, u32 *payload_len)
{
  u32 w0 = uhsif_le32(hdr);
  u32 w1 = uhsif_le32(hdr + 4);
  u32 w2 = uhsif_le32(hdr + 8);
  u32 w3 = uhsif_le32(hdr + 12);
  u32 len = (w3 >> 12) & 0xfffu;

  (void)s;

  // w0[31:16] must be the crc16 of w1..w3 and w0[15:0] the block magic.
  if (!uhsif_blk_hdr_ok(w0, w1, w2, w3))
    return false;

  // Bits [31:12] of w1 are reserved (channel_mask is 12 bits).
  if (w1 & 0xfffff000u)
    return false;

  // Zero-length blocks are ACKs; data blocks must be within the legal range.
  if (len != 0 && !(len >= UHSIF_MIN_PAYLOAD_WORDS && len <= UHSIF_MAX_PAYLOAD_WORDS))
    return false;

  *payload_len = len;

  return true;
}

//-----------------------------------------------------------------------------
static void accept_block(stream *s, u32 payload_len)
{
  const u8 *hdr = buf_at(s, 0);
  u32 seq = uhsif_blk_seq(hdr);
  int span = UHSIF_ACK_SIZE + 4 * (int)payload_len;

  if (s->have_seq)
  {
    u8 expected = (u8)(s->last_seq + 1);

    // Sequence continuity is shared between ACK and data blocks: the FPGA
    // increments its counter in S_TX_END for both transmit paths.
    if ((u8)seq != expected)
    {
      s->cb.rsync_cb(s->cb.user);
      log_print("stream: sequence jump %u -> %u, resynchronizing", (unsigned)s->last_seq, (unsigned)seq);
      s->have_seq = false;
      s->good = 0;
    }
  }

  s->last_seq = (u8)seq;
  s->have_seq = true;

  if (!s->good)
  {
    // A resync is only considered stable after two consecutive good blocks.
    s->good = 1;
  }
  else if (s->good < 2)
  {
    s->good++;
  }

  if (payload_len == 0)
    s->cb.ack_cb(s->cb.user);
  else
    s->cb.data_cb(s->cb.user, hdr + UHSIF_ACK_SIZE, 4 * (int)payload_len);

  s->head += span;
  s->len -= span;

  s->state = STREAM_BLOCK;
}

//-----------------------------------------------------------------------------
static void process_available(stream *s)
{
  while (s->len >= UHSIF_ACK_SIZE)
  {
    if (s->state == STREAM_BLOCK)
    {
      u32 payload_len;
      u32 full_size;
      int valid;

      valid = header_valid(s, buf_at(s, 0), &payload_len);
      full_size = UHSIF_ACK_SIZE + 4 * payload_len;

      if (valid && (u32)s->len < full_size)
      {
        // The full block is not here yet, wait for more data.
        if (full_size <= (u32)s->cap)
          return;

        // Block larger than the staging buffer should not happen.
        s->cb.rsync_cb(s->cb.user);
        log_print("stream: oversized block (%u bytes), resynchronizing", (unsigned)full_size);
        s->have_seq = false;
        s->good = 0;
        s->state = STREAM_SCAN;
        continue;
      }

      if (!valid)
      {
        // Invalid header at an aligned position: report and rescan.
        s->cb.rsync_cb(s->cb.user);
        log_print("stream: invalid block header at %d bytes, resynchronizing", s->head);
        s->have_seq = false;
        s->good = 0;
        s->state = STREAM_SCAN;
        continue;
      }

      accept_block(s, payload_len);
      continue;
    }

    // STREAM_SCAN: search for the next block header.  Scan bytewise so that
    // a completely misaligned stream can recover; v2 has no fixed magic word,
    // so first filter on the w0 low half-word and let header_valid() do the
    // full crc16 check on each candidate.
    {
      int i = 0;
      int found = -1;

      for (i = 0; i <= s->len - (int)sizeof(u32); i++)
      {
        if ((u16)uhsif_le32(buf_at(s, i)) == UHSIF_BLK_MAGIC16)
        {
          found = i;
          break;
        }
      }

      if (found < 0)
      {
        // Keep the tail in case a header candidate spans the chunk boundary.
        int keep = os_min(s->len, SCAN_KEEP_TAIL);

        if (s->head + s->len > 0 && keep + UHSIF_ACK_SIZE <= s->cap)
        {
          memmove(s->buf, &s->buf[s->head + s->len - keep], (size_t)keep);
          s->head = 0;
          s->len = keep;
        }
        return;
      }

      // Candidate header found.  Try to validate it in full.
      if (s->len - found < UHSIF_ACK_SIZE)
      {
        // Need more header bytes; move the candidate to the front.
        memmove(s->buf, &s->buf[s->head + found], (size_t)(s->len - found));
        s->head = 0;
        s->len = s->len - found;
        return;
      }

      {
        u32 payload_len;

        if (!header_valid(s, buf_at(s, found), &payload_len))
        {
          // Bogus magic inside the data; skip past it and keep scanning.
          s->head += found + 1;
          s->len -= found + 1;
          continue;
        }

        if (s->len - found < UHSIF_ACK_SIZE + 4 * (int)payload_len)
        {
          // Block not fully received yet; hold at the candidate.
          memmove(s->buf, &s->buf[s->head + found], (size_t)(s->len - found));
          s->head = 0;
          s->len = s->len - found;
          return;
        }

        // Drop everything before the candidate and accept the block.
        s->head += found;
        s->len -= found;
        accept_block(s, payload_len);
      }
    }
  }
}

//-----------------------------------------------------------------------------
void stream_feed(stream *s, const u8 *data, int size)
{
  while (size > 0)
  {
    // Compact first so that every capacity check below uses the plain
    // "len" accounting; head may be non-zero after process_available()
    // consumed leading bytes, and mixing head+len into the write bounds is
    // what allowed an out-of-bounds memcpy at high throughput.
    if (s->head != 0)
      compact(s);

    if (s->len + size <= s->cap)
    {
      memcpy(&s->buf[s->len], data, (size_t)size);
      s->len += size;
      break;
    }

    // Buffer full: copy as much as fits and process it, then continue.
    int room = s->cap - s->len;
    int part = os_min(size, room);

    memcpy(&s->buf[s->len], data, (size_t)part);
    s->len += part;
    data += part;
    size -= part;

    if (size == 0)
      break;

    process_available(s);

    // Make room for the remainder without losing pending bytes.  After
    // process_available() the buffer can hold an incomplete but valid block
    // (up to ~16 KiB) in STREAM_BLOCK state, or a held header candidate in
    // STREAM_SCAN.  The previous "keep only the last 3 bytes" drop destroyed
    // both: under sustained traffic (TRANSFER_SIZE == staging size) every
    // buffer-full event lost a whole in-progress block and forced a spurious
    // resync + "USB link packet loss" report.  Compaction moves at most one
    // maximum-size block (~16 KiB) to the front and preserves everything.
    compact(s);
  }

  process_available(s);
}