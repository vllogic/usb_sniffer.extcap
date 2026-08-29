// SPDX-License-Identifier: BSD-3-Clause
// Minimal pcapng writer producing the exact same block layout as the
// upstream usb-sniffer project (SHB / IDB / EPB + UPPER_PDU "info" stream).

#ifndef PCAPNG_H
#define PCAPNG_H

#include "os_common.h"

typedef struct pcapng pcapng;

// Link type (DLT) constants.
#define LINKTYPE_USB_2_0               288
#define LINKTYPE_USB_2_0_LOW_SPEED     293
#define LINKTYPE_USB_2_0_FULL_SPEED    294
#define LINKTYPE_USB_2_0_HIGH_SPEED    295
#define LINKTYPE_WIRESHARK_UPPER_PDU   252

// Open the output file for writing.  Returns NULL on failure.
pcapng *pcapng_open(const char *path);

// Write the section header block, the USB interface description block and
// the info interface description block, then flush any blocks that were
// buffered before this call.  Nothing is written to the file before this.
void pcapng_begin(pcapng *p, int usb_link_type);

// Pretty-print helpers (both go to interface id 0).
void pcapng_write_epb(pcapng *p, u64 ts, const u8 *data, int size);

// Out-of-band info string (interface id 1, DLT 252 UPPER_PDU/syslog).
void pcapng_write_info(pcapng *p, u64 ts, const char *str, int size);

// Flush the underlying stream (useful for live pipes).
void pcapng_flush(pcapng *p);

void pcapng_close(pcapng *p);

#endif // PCAPNG_H