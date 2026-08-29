// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.
// gen1 (ataradov USB Sniffer, FX2LP + FPGA) libusb backend.
// Adapted for the merged plugin: bcdDevice-filtered device matching and a
// cooperative stop flag instead of an unconditional busy loop.

#ifndef GEN1_USB_H
#define GEN1_USB_H

#include "os_common.h"

/*- Definitions -------------------------------------------------------------*/
#define USB_EP0_SIZE   64

#define GEN1_VID       0x1209
#define GEN1_PID       0x6688
#define GEN1_BCD       0x0001

#define GEN1_VID_LEGACY  0x6666
#define GEN1_PID_LEGACY  0x6620

#define FX2LP_VID      0x04b4
#define FX2LP_PID      0x8613

/*- Prototypes --------------------------------------------------------------*/
void usb_init(void);

/* Open a device matching vid/pid; for the shared 1209:6688 pair only the
 * gen1 bcdDevice release is accepted.  bcd_accept == 0 means any version. */
bool usb_open(int vid, int pid, int bcd_accept);
void usb_close(void);

/* Open any connected gen1 capture device (current or legacy release). */
void open_capture_device(void);

void usb_fx2lp_reset(bool reset);
void usb_fx2lp_sram_read(int addr, u8 *data, int size);
void usb_fx2lp_sram_write(int addr, u8 *data, int size);

void usb_i2c_read(int addr, u8 *data, int size);
void usb_i2c_write(int addr, u8 *data, int size);

void usb_jtag_enable(bool enable);
void usb_jtag_request(u8 *data, int count);
void usb_jtag_response(u8 *data, int count);

void usb_ctrl(int index, int value);

void usb_flush_data(void);
void usb_data_transfer(void);

void usb_ctrl_init(void);

void usb_speed_test(void);

#endif // GEN1_USB_H