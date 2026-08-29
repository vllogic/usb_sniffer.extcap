// SPDX-License-Identifier: BSD-3-Clause
// Basic types, helpers and portability wrappers shared by all modules.

#ifndef OS_COMMON_H
#define OS_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

typedef uint8_t    u8;
typedef int8_t     s8;
typedef uint16_t   u16;
typedef int16_t    s16;
typedef uint32_t   u32;
typedef int32_t    s32;
typedef uint64_t   u64;
typedef int64_t    s64;
typedef float      f32;
typedef double     f64;

#define ARRAY_SIZE(x)  ((int)(sizeof(x) / sizeof(0[x])))

#define os_assert(x) \
  do \
  { \
    if (!(x)) \
    { \
      fprintf(stderr, "%s:%d: assertion '%s' failed\n", __FILE__, __LINE__, #x); \
      exit(1); \
    } \
  } while (0)

#define os_min(a, b)  ((a) < (b) ? (a) : (b))
#define os_max(a, b)  ((a) > (b) ? (a) : (b))

/* If cond is false: print message to stderr and exit(1). */
void os_check(bool cond, const char *fmt, ...);

/* Print message to stderr and exit(1). */
void os_error(const char *fmt, ...) __attribute__((noreturn));

void *os_alloc(int size);
void *os_realloc(void *data, int size);
void os_free(void *data);
char *os_strdup(const char *str);

s64 os_get_time_ms(void);
/* Millisecond wall clock (same value as os_get_time_ms; gen1 alias). */
s64 os_get_time(void);
void os_sleep(int ms);

/* Deterministic PRNG used by the gen1 transfer-rate test: the FPGA pattern
 * generator produces the same sequence seeded with 0, so the verify must
 * reproduce it exactly. */
u16 os_rand16(u16 seed);

/* Read a whole file into a fresh allocation (null-padded footer included). */
int os_file_read_all(const char *name, u8 **data);

/* Find a substring in a byte buffer (gen1 bitstream/JED signature scan). */
u8 *find_str(u8 *buf, int size, char *str);

/* Log message to stderr (never stdout, which is reserved for extcap/Wireshark).
 * Suppressed (log_set_quiet) while running as a live extcap capture: Wireshark
 * surfaces any extcap stderr output as an error report, so routine status
 * lines ("device opened", "cmd acknowledged", ...) must not be emitted there.
 * USB_SNIFFER_LOG=<file> redirects logs to that file instead. */
void log_print(const char *fmt, ...);
void log_set_quiet(bool quiet);
void log_open_file(const char *name);

#endif // OS_COMMON_H