// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.
// gen1 capture control register bits and the capture engine entry points.

#ifndef GEN1_CAPTURE_H
#define GEN1_CAPTURE_H

#include "os_common.h"

/*- Definitions -------------------------------------------------------------*/
enum
{
  CaptureCtrl_Reset  = 0,
  CaptureCtrl_Enable = 1,
  CaptureCtrl_Speed0 = 2,
  CaptureCtrl_Speed1 = 3,
  CaptureCtrl_Test   = 4,
};

/*- Prototypes --------------------------------------------------------------*/
/* Open the device, run the init sequence, write the pcapng headers and
 * stream until stopped (the merged SIGINT handler) or a capture limit. */
bool capture_start(void);

/* Feed raw capture bytes from the bulk endpoint into the frame parser. */
void capture_callback(u8 *data, int size);

#endif // GEN1_CAPTURE_H