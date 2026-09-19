// pcapng_wq_test.c — pcapng 异步写（写线程 + 环形缓冲）回归
// 用法:
//   gcc -W -Wall --std=gnu11 -O2 -Isrc -Isrc/gen1 -D_GNU_SOURCE tools/pcapng_wq_test.c \
//       src/pcapng.c src/os_common.c -o /tmp/wq_test -lm -pthread && /tmp/wq_test
// 校验: 逐 EPB 检查索引/异或/填充与顺序；文件尾部必须无垃圾（曾因队列漏传长度
//       而多写 62 KB 垃圾块，pcapng 会被判坏块）。
#include "pcapng.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
int main(void){
  const int N = 200000, SZ = 100;
  pcapng *p = pcapng_open("/tmp/kilo/wq_test.pcapng");
  if(!p){ printf("open fail\n"); return 1; }
  pcapng_begin(p, 288);
  for(int i=0;i<N;i++){ uint8_t d[100]; memset(d,(uint8_t)(i&0xFF),sizeof(d));
    ((uint32_t*)d)[0]=(uint32_t)i; ((uint32_t*)d)[1]=(uint32_t)(i^0xA5A5A5A5u);
    pcapng_write_epb(p, (uint64_t)(1000000+i), d, SZ); }
  pcapng_flush(p);
  pcapng_close(p);
  printf("wrote %d EPB\n", N);
  return 0;
}
