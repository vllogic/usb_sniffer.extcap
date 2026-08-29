// SPDX-License-Identifier: BSD-3-Clause

#include "pcapng.h"

#define PCAPNG_BLOCK_BUF_SIZE  4096

struct pcapng
{
  FILE  *fd;
  bool   begun;

  // Current block assembly buffer.
  u8     block[PCAPNG_BLOCK_BUF_SIZE];
  int    ptr;

  // Blocks written before pcapng_begin() are staged here until the SHB/IDB
  // headers are flushed to the file, preserving SHB-first ordering even if
  // the device starts streaming right after the FPGA gets enabled.
  u8    *pend;
  int    pend_len;
  int    pend_cap;
};

//-----------------------------------------------------------------------------
static void put_pad(pcapng *p)
{
  while (p->ptr % 4)
    p->block[p->ptr++] = 0;
}

//-----------------------------------------------------------------------------
static void put_half(pcapng *p, u16 value)
{
  p->block[p->ptr + 0] = (u8)value;
  p->block[p->ptr + 1] = (u8)(value >> 8);
  p->ptr += 2;
}

//-----------------------------------------------------------------------------
static void put_word(pcapng *p, u32 value)
{
  p->block[p->ptr + 0] = (u8)value;
  p->block[p->ptr + 1] = (u8)(value >> 8);
  p->block[p->ptr + 2] = (u8)(value >> 16);
  p->block[p->ptr + 3] = (u8)(value >> 24);
  p->ptr += 4;
}

//-----------------------------------------------------------------------------
static void put_data(pcapng *p, const u8 *data, int size)
{
  memcpy(&p->block[p->ptr], data, (size_t)size);
  p->ptr += size;
}

//-----------------------------------------------------------------------------
static void put_option(pcapng *p, int index, const char *str)
{
  int len = (int)strlen(str);

  put_half(p, (u16)index);
  put_half(p, (u16)len);
  put_data(p, (const u8 *)str, len);
  put_pad(p);
}

//-----------------------------------------------------------------------------
static void send_buffer(pcapng *p)
{
  int size = p->ptr + 4;

  put_word(p, (u32)size);         // trailing block total length word
  p->block[4] = (u8)size;         // patch the leading block total length
  p->block[5] = (u8)(size >> 8);
  p->block[6] = (u8)(size >> 16);
  p->block[7] = (u8)(size >> 24);

  if (p->begun)
  {
    int res = (int)fwrite(p->block, 1, (size_t)p->ptr, p->fd);
    os_check(res == p->ptr, "pcapng write() error");
  }
  else
  {
    if (p->pend_len + p->ptr > p->pend_cap)
    {
      p->pend_cap = p->pend_cap ? p->pend_cap * 2 : 65536;
      p->pend = os_realloc(p->pend, p->pend_cap);
    }
    memcpy(&p->pend[p->pend_len], p->block, (size_t)p->ptr);
    p->pend_len += p->ptr;
  }

  p->ptr = 0;
}

//-----------------------------------------------------------------------------
static void write_block_type(pcapng *p, u32 type)
{
  put_word(p, type);
  put_word(p, 0); // block total length placeholder
}

//-----------------------------------------------------------------------------
static void write_file_header(pcapng *p)
{
  write_block_type(p, 0x0a0d0d0a);              // SHB
  put_word(p, 0x1a2b3c4d);                      // byte order magic
  put_half(p, 1);                               // major version
  put_half(p, 0);                               // minor version
  put_word(p, 0xffffffff);                      // section length (unknown)
  put_word(p, 0xffffffff);
  put_option(p, 0x0002, "USB Sniffer 2"); // shb_hardware
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
static void write_usb_header(pcapng *p, int link_type)
{
  write_block_type(p, 1);                       // IDB
  put_half(p, (u16)link_type);
  put_half(p, 0);                               // reserved
  put_word(p, 0xffff);                          // snap length
  put_option(p, 0x0002, "usb");                 // if_name
  put_option(p, 0x0003, "Hardware USB interface"); // if_description
  put_half(p, 9);                               // if_tsresol option code
  put_half(p, 1);                               // option length
  put_word(p, 9);                               // resolution = 10^-9 s
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
static void write_info_header(pcapng *p)
{
  write_block_type(p, 1);                       // IDB
  put_half(p, (u16)LINKTYPE_WIRESHARK_UPPER_PDU);
  put_half(p, 0);                               // reserved
  put_word(p, 0xffff);                          // snap length
  put_option(p, 0x0002, "info");                // if_name
  put_option(p, 0x0003, "Out of band information"); // if_description
  put_half(p, 9);                               // if_tsresol option code
  put_half(p, 1);                               // option length
  put_word(p, 9);                               // resolution = 10^-9 s
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
pcapng *pcapng_open(const char *path)
{
  pcapng *p = os_alloc(sizeof(pcapng));

  p->fd = fopen(path, "wb");
  os_check(p->fd, "could not open FIFO pipe '%s'", path);

  return p;
}

//-----------------------------------------------------------------------------
void pcapng_begin(pcapng *p, int usb_link_type)
{
  os_assert(!p->begun);

  // Mark the stream begun before writing the section header: the header
  // blocks must go to the file/pipe directly, ahead of any pre-session EPBs
  // staged during the FPGA init phase (staging them would put the SHB after
  // those blocks and break the pcapng magic-first parse).
  p->begun = true;

  write_file_header(p);
  write_usb_header(p, usb_link_type);
  write_info_header(p);

  if (p->pend_len)
  {
    int res = (int)fwrite(p->pend, 1, (size_t)p->pend_len, p->fd);
    os_check(res == p->pend_len, "pcapng write() error");
  }
}

//-----------------------------------------------------------------------------
void pcapng_write_epb(pcapng *p, u64 ts, const u8 *data, int size)
{
  write_block_type(p, 6);                       // EPB
  put_word(p, 0);                               // interface id 0
  put_word(p, (u32)(ts >> 32));                 // timestamp upper
  put_word(p, (u32)ts);                         // timestamp lower
  put_word(p, (u32)size);                       // captured packet length
  put_word(p, (u32)size);                       // original packet length
  put_data(p, data, size);
  put_pad(p);
  put_option(p, 0x0000, "");
  send_buffer(p);
}

//-----------------------------------------------------------------------------
void pcapng_write_info(pcapng *p, u64 ts, const char *str, int size)
{
  static const u8 hdr[] = { 0, 12, 0, 6, 's', 'y', 's', 'l', 'o', 'g', 0, 0, 0, 0 };

  write_block_type(p, 6);                       // EPB
  put_word(p, 1);                               // interface id 1
  put_word(p, (u32)(ts >> 32));                 // timestamp upper
  put_word(p, (u32)ts);                         // timestamp lower
  put_word(p, (u32)(sizeof(hdr) + size));       // captured packet length
  put_word(p, (u32)(sizeof(hdr) + size));       // original packet length
  put_data(p, hdr, sizeof(hdr));
  put_data(p, (const u8 *)str, size);
  put_pad(p);
  send_buffer(p);
}

//-----------------------------------------------------------------------------
void pcapng_flush(pcapng *p)
{
  if (p->begun && p->fd)
    fflush(p->fd);
}

//-----------------------------------------------------------------------------
void pcapng_close(pcapng *p)
{
  if (p->fd)
  {
    fflush(p->fd);
    fclose(p->fd);
  }

  os_free(p->pend);
  os_free(p);
}