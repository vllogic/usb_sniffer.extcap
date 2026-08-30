// SPDX-License-Identifier: BSD-3-Clause

#include "os_common.h"
#include "device.h"

#include <libusb.h>

#define USB_VID_VLLOGIC     0x1209
#define USB_PID_VLLOGIC     0x6688
#define USB_VID_LEGACY      0x6666   // first-generation capture device
#define USB_PID_LEGACY      0x6620
#define USB_VID_FX2LP       0x04b4   // unconfigured FX2LP bootstrap mode
#define USB_PID_FX2LP       0x8613

#define USB_BCD_GEN1        0x0001   // firmware/usb_descriptors.h
#define USB_BCD_GEN2        0x0602   // DEF_USB_BCD in Common/usb_desc.h

//-----------------------------------------------------------------------------
bool device_is_gen2(int vid, int pid, int bcd)
{
  return (vid == USB_VID_VLLOGIC) && (pid == USB_PID_VLLOGIC) && (bcd == USB_BCD_GEN2);
}

//-----------------------------------------------------------------------------
static bool gen1_classify(int vid, int pid, int bcd)
{
  if (vid == USB_VID_LEGACY && pid == USB_PID_LEGACY)
    return true;

  if (vid == USB_VID_VLLOGIC && pid == USB_PID_VLLOGIC)
    return bcd == USB_BCD_GEN1;

  return false;
}

//-----------------------------------------------------------------------------
device_kind device_probe(void)
{
  libusb_device **devices = NULL;
  bool gen1 = false, gen2 = false, fx2lp = false;
  int rc = libusb_init(NULL);

  if (rc < 0)
    os_error("libusb_init(): %s", libusb_error_name(rc));

  int count = libusb_get_device_list(NULL, &devices);
  if (count < 0)
    os_error("libusb_get_device_list(): %s", libusb_error_name(count));

  for (int i = 0; i < count; i++)
  {
    struct libusb_device_descriptor desc;

    if (libusb_get_device_descriptor(devices[i], &desc) < 0)
      continue;

    if (gen1_classify(desc.idVendor, desc.idProduct, desc.bcdDevice))
      gen1 = true;

    if (desc.idVendor == USB_VID_FX2LP && desc.idProduct == USB_PID_FX2LP)
      fx2lp = true;   // unconfigured FX2LP bootstrap: gen1 family, but not a
                      // capture device until the firmware is loaded; 04b4:8613
                      // is the default descriptor of every FX2LP, so a board
                      // unrelated to this project matches it too

    if (device_is_gen2(desc.idVendor, desc.idProduct, desc.bcdDevice))
      gen2 = true;

    if (gen1 && gen2)
      break;
  }

  libusb_free_device_list(devices, 1);
  libusb_exit(NULL);

  if (gen1 && gen2)
    return Device_Both;
  if (gen1)
    return Device_Gen1;   // a configured gen1 outranks a bare FX2LP
  if (gen2)
    return Device_Gen2;   // an unrelated FX2LP on the bus must not block gen2
  if (fx2lp)
    return Device_Fx2lp_Only;
  return Device_None;
}