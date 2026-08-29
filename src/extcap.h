// SPDX-License-Identifier: BSD-3-Clause
// Command line options and the Wireshark extcap protocol queries.
// One capture interface covering both hardware generations; the engine is
// selected automatically at capture time by probing VID/PID + bcdDevice:
//
//   gen1 (ataradov USB Sniffer class, FX2LP + FPGA): bcdDevice 0x0001 on
//        1209:6688, legacy 6666:6620, or an unconfigured FX2LP 04b4:8613
//   gen2 (Vllogic USB Sniffer 2, CH32H417 + UHSIF): bcdDevice 0x0602 on
//        1209:6688
//
// The capture semantics (speed / fold / exclude / trigger / limit) are
// shared.  The extcap transcript is emitted on stdout; logging goes to
// stderr.

#ifndef EXTCAP_H
#define EXTCAP_H

#include "os_common.h"

#define INTERFACE_NAME       "usb_sniffer"
#define VENDOR_NAME           "Vllogic"

#define EXTCAP_VERSION       "2.0"
#define EXTCAP_URL           "https://github.com/vllogic/usb_sniffer.extcap"

typedef struct
{
  bool  help;
  char *speed;
  bool  fold_empty;
  bool  exclude_line_state;
  char *limit;
  char *trigger;
  bool  test;

  bool  extcap_version;
  bool  extcap_dlts;
  bool  extcap_interfaces;
  char *extcap_interface;
  bool  extcap_config;
  bool  extcap_capture;
  char *extcap_fifo;

  char *replay;      // optional pre-recorded gen2 upstream stream (offline)

  char *mcu_sram;    // gen1: upload FX2LP firmware into the SRAM and run it
  char *mcu_eeprom;  // gen1: program FX2LP firmware into the EEPROM
  char *fpga_sram;   // gen1: upload BIT file into the FPGA SRAM
  char *fpga_flash;  // gen1: program JED file into the FPGA flash
  bool  fpga_erase;  // gen1: erase FPGA flash

  int   capture_speed;
  int   capture_trigger;
  s64   capture_limit;
} Options;

extern Options g_opt;

void parse_command_line(int argc, char *argv[]);

// Returns true if one of the --extcap-* queries was answered.
bool handle_extcap_request(void);

#endif // EXTCAP_H