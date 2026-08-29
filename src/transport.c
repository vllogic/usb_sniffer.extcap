// SPDX-License-Identifier: BSD-3-Clause

#include "transport.h"
#include "transport_internal.h"

//-----------------------------------------------------------------------------
bool transport_open(transport *t)
{
  return t->ops->open(t);
}

//-----------------------------------------------------------------------------
void transport_discard(transport *t)
{
  t->ops->discard(t);
}

//-----------------------------------------------------------------------------
void transport_stream_mode(transport *t)
{
  t->ops->stream_mode(t);
}

//-----------------------------------------------------------------------------
bool transport_events(transport *t, long timeout_ms)
{
  return t->ops->events(t, timeout_ms);
}

//-----------------------------------------------------------------------------
int transport_write(transport *t, const u8 *data, int size)
{
  return t->ops->write(t, data, size);
}

//-----------------------------------------------------------------------------
bool transport_alive(const transport *t)
{
  return t->ops->alive(t);
}

//-----------------------------------------------------------------------------
void transport_close(transport *t)
{
  if (t)
  {
    t->ops->close(t);
    os_free(t);
  }
}