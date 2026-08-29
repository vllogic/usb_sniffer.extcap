// SPDX-License-Identifier: BSD-3-Clause
// Internal transport layout shared by transport.c and its two backends
// (libusb and replay).  Not part of the public API.

#ifndef TRANSPORT_INTERNAL_H
#define TRANSPORT_INTERNAL_H

#include "transport.h"

struct transport
{
  transport_callbacks cb;
  void               *priv;     // backend-private data
  transport_ops      *ops;      // backend operation table
};

#endif // TRANSPORT_INTERNAL_H