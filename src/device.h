// SPDX-License-Identifier: BSD-3-Clause
// Hardware identification for the merged two-generation sniffer plugin.
//
// Both generations share VID 0x1209 / PID 0x6688, so the version field
// (bcdDevice) of the device descriptor is the discriminator:
//
//   gen1 (ataradov USB Sniffer, FX2LP + FPGA firmware):
//       VID 0x1209, PID 0x6688, bcdDevice 0x0001  (firmware/usb_descriptors.h)
//       VID 0x6666, PID 0x6620 (legacy capture device, any bcdDevice)
//       VID 0x04b4, PID 0x8613 (unconfigured FX2LP bootstrap mode)
//   gen2 (USB Sniffer 2, CH32H417): VID 0x1209, PID 0x6688,
//       bcdDevice 0x0602  (DEF_USB_BCD in usb_desc.h)
//
// device_probe() scans the USB bus with a private libusb context and
// reports which generation(s) are present.  Each transport backend applies
// the same filtering when it opens its own device, so a merged run never
// grabs the other generation's hardware.

#ifndef DEVICE_H
#define DEVICE_H

typedef enum
{
  Device_None = 0,
  Device_Gen1,        // ataradov-class sniffer only
  Device_Gen2,        // USB Sniffer 2 only
  Device_Both,        // both generations are on the bus
  Device_Fx2lp_Only,  // only an unconfigured FX2LP (04b4:8613) is on the bus;
                      // it belongs to the gen1 family but carries no capture
                      // firmware, so it may well be an unrelated FX2LP device
} device_kind;

device_kind device_probe(void);

/* True if the given VID/PID/bcdDevice triple identifies a gen2 device. */
bool device_is_gen2(int vid, int pid, int bcd);

#endif // DEVICE_H