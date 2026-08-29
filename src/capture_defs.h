// SPDX-License-Identifier: BSD-3-Clause
// Shared capture semantics (same values as the upstream usb-sniffer
// project).  The speed enums double as the CAPTURE_SPEED command parameter
// (0=LS, 1=FS, 2=HS, 3=AUTO) and as the DLT mapping selector.

#ifndef CAPTURE_DEFS_H
#define CAPTURE_DEFS_H

enum
{
  CaptureSpeed_LS    = 0,   // maps to DLT 293
  CaptureSpeed_FS    = 1,   // maps to DLT 294
  CaptureSpeed_HS    = 2,   // maps to DLT 295
  CaptureSpeed_Reset = 3,   // auto / bus reset state, maps to DLT 288
};

enum
{
  CaptureTrigger_Disabled,
  CaptureTrigger_Low,
  CaptureTrigger_High,
  CaptureTrigger_Falling,
  CaptureTrigger_Rising,
};

#endif // CAPTURE_DEFS_H