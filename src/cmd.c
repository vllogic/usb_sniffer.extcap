// SPDX-License-Identifier: BSD-3-Clause

#include "cmd.h"
#include "transport.h"
#include "uhsif.h"

//-----------------------------------------------------------------------------
void cmd_init(cmd *c, transport *tr)
{
  c->tr = tr;
  c->seq = 0;
  c->waiting = false;
  c->ack_seen = false;
  c->fatal = false;
  c->suppress = true;
}

//-----------------------------------------------------------------------------
bool cmd_input_suppressed(const cmd *c)
{
  return c->suppress;
}

//-----------------------------------------------------------------------------
void cmd_ack_event(cmd *c)
{
  if (c->waiting)
    c->ack_seen = true;
}

//-----------------------------------------------------------------------------
static void build_packet(cmd *c, u8 *pkt, int id, u32 param)
{
  u32 w1 = ((u32)c->seq << 8) | (u32)id;
  u32 w3 = 0;                                  // {20'b0, payload_len[11:0]}
  u32 w0 = ((u32)uhsif_hdr_crc16(w1, param, w3) << 16) | (u32)UHSIF_CMD_MAGIC16;

  uhsif_put_le32(&pkt[0], w0);
  uhsif_put_le32(&pkt[4], w1);
  uhsif_put_le32(&pkt[8], param);
  uhsif_put_le32(&pkt[12], w3);
}

//-----------------------------------------------------------------------------
void cmd_tx_quiet(cmd *c, int id, u32 param)
{
  u8 pkt[UHSIF_CMD_SIZE];

  build_packet(c, pkt, id, param);

  if (transport_write(c->tr, pkt, UHSIF_CMD_SIZE) < 0)
    log_print("cmd: quiet command 0x%02x submit failed", id);
}

//-----------------------------------------------------------------------------
bool cmd_exec(cmd *c, int id, u32 param)
{
  u8 pkt[UHSIF_CMD_SIZE];

  for (int attempt = 0; attempt < UHSIF_CMD_RETRIES; attempt++)
  {
    build_packet(c, pkt, id, param);

    if (attempt > 0)
      log_print("cmd: retrying command 0x%02x (attempt %d)", id, attempt + 1);

    if (transport_write(c->tr, pkt, UHSIF_CMD_SIZE) < 0)
      return false;

    c->suppress = false;
    c->waiting = true;
    c->ack_seen = false;

    s64 deadline = os_get_time_ms() + UHSIF_CMD_TIMEOUT_MS;

    while ((s64)os_get_time_ms() < deadline)
    {
      transport_events(c->tr, 20);

      if (c->ack_seen)
      {
        c->waiting = false;
        c->seq++;
        return true;
      }

      if (!transport_alive(c->tr))
        break;
    }

    c->waiting = false;

    if (c->ack_seen)
    {
      // An ACK appeared at (or just after) the deadline - treat as success
      // so a retry does not re-execute a command the FPGA already applied.
      c->seq++;
      return true;
    }

    if (!transport_alive(c->tr))
    {
      c->fatal = true;
      return false;
    }
  }

  c->fatal = true;
  log_print("cmd: command 0x%02x not acknowledged", id);

  return false;
}