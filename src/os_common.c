// SPDX-License-Identifier: BSD-3-Clause

#include "os_common.h"
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

void os_check(bool cond, const char *fmt, ...)
{
  if (cond)
    return;

  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);

  exit(1);
}

void os_error(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);

  exit(1);
}

void *os_alloc(int size)
{
  void *data = malloc((size_t)size);

  os_check(data != NULL, "out of memory trying to allocate %d bytes", size);

  memset(data, 0, (size_t)size);

  return data;
}

void *os_realloc(void *data, int size)
{
  data = realloc(data, (size_t)size);

  os_check(data != NULL, "out of memory trying to re-allocate %d bytes", size);

  return data;
}

void os_free(void *data)
{
  free(data);
}

char *os_strdup(const char *str)
{
  char *res = strdup(str);
  os_assert(res);
  return res;
}

s64 os_get_time_ms(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return (s64)tv.tv_sec * 1000 + (s64)tv.tv_usec / 1000;
}

s64 os_get_time(void)
{
  return os_get_time_ms();
}

void os_sleep(int ms)
{
  struct timespec ts;

  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000;

  nanosleep(&ts, NULL);
}

u16 os_rand16(u16 seed)
{
  static u16 state = 0x6c41;

  if (seed)
    state = seed;

  state ^= state << 7;
  state ^= state >> 9;
  state ^= state << 8;

  return state;
}

int os_file_read_all(const char *name, u8 **data)
{
  FILE *fd = fopen(name, "rb");
  os_check(fd != NULL, "os_file_read_all(): %s", strerror(errno));

  os_check(fseek(fd, 0, SEEK_END) == 0, "os_file_read_all(): seek failed");
  long size = ftell(fd);
  os_check(size >= 0, "os_file_read_all(): tell failed");
  os_check(fseek(fd, 0, SEEK_SET) == 0, "os_file_read_all(): seek failed");

  *data = os_alloc((int)size + 8192);

  size_t res = fread(*data, 1, (size_t)size, fd);
  os_check(res == (size_t)size, "os_file_read_all(): failed to read entire file");

  fclose(fd);

  return (int)size;
}

u8 *find_str(u8 *buf, int size, char *str)
{
  int len = strlen(str);

  if (size == 0 || len == 0 || size < len)
    return NULL;

  // The last valid start offset is size - len (match ends exactly at the
  // buffer end), hence "<="; the previous "<" silently missed that case.
  for (int i = 0; i <= (size - len); i++)
  {
    if (memcmp(buf + i, str, (size_t)len) == 0)
      return buf + i;
  }

  return NULL;
}

static bool g_log_quiet = false;
static FILE *g_log_fd = NULL;   // NULL = stderr

void log_set_quiet(bool quiet)
{
  g_log_quiet = quiet;
}

/* Redirect routine logs to a file (USB_SNIFFER_LOG).  A redirect file keeps
 * receiving logs even when quiet mode is on (extcap capture): quiet only
 * silences the stderr path, which Wireshark would report as an error. */
void log_open_file(const char *name)
{
  if (!name || !name[0])
    return;

  g_log_fd = fopen(name, "a+");

  if (!g_log_fd)
    fprintf(stderr, "Error: could not open log file '%s': %s\n", name, strerror(errno));
}

void log_print(const char *fmt, ...)
{
  if (g_log_quiet && !g_log_fd)
    return;

  FILE *fd = g_log_fd ? g_log_fd : stderr;

  va_list args;
  va_start(args, fmt);
  vfprintf(fd, fmt, args);
  va_end(args);
  fprintf(fd, "\n");
  fflush(fd);
}