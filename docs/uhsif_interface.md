# UHSIF 接口技术说明 · 使用限制 · 性能测试指南

> 适用硬件：gen2 **Vllogic USB Sniffer 2**（CH32H417 固件 + H7P20 FPGA），协议 **v2.3**。
> 关联文档：字节级协议定义见 [`protocol.md`](protocol.md)；本文侧重**实现说明、约束与
> 性能测试操作**，面向固件/FPGA 维护者与第三方上位机集成者。
>
> 文档基线：2026-09-11，`uhsif_dev` 分支（批量块长度下限放开到 16 B 之后）。

---

## 1. 接口概述

### 1.1 拓扑

```
PC ──EP1 OUT──▶ CH32H417(DMA 透传) ──UHSIF L1──▶ FPGA(H7P20)
PC ◀──EP1 IN─── CH32H417(DMA 透传) ◀──UHSIF L0─── FPGA(H7P20)
```

- 设备为 **vendor class**，无内核驱动；端点 `EP1 OUT(0x01)` / `EP1 IN(0x81)`。
- CH32 固件对上/下行内容**零语义整包透传**：不封装、不改字节、不改长度。
- 命令面（16 B 命令包）与下行批量块复用 **EP1 OUT / UHSIF line1**，**串行发送**。

### 1.2 链路与端点参数

| 项 | 值 |
|---|---|
| VID:PID | `0x1209 / 0x6688`（bcdDevice 区分两代；gen2 rev 0x0602）|
| UHSIF 时钟 | 实测 **118.18 MHz**（`pll_fixed.v`；非标称 125 MHz）|
| UHSIF 数据宽度 | 32 bit/word，**全 little-endian**，word 低字节先到 USB |
| UHSIF 线速上限 | 118.18 MHz × 32 bit ≈ **472.7 MB/s**（line0/line1 半双工共享）|
| 单次 UHSIF line 传输上限 | **4096 words = 16 KiB**（USBSS 每 16 KiB 强制分链）|
| USB3 SuperSpeed | bulk 1024 B × burst 15 |
| USB2 High Speed | EP1 按 512 B 分片；块 payload 建议 ≤504 B |

### 1.3 主机侧强制要求（第三方上位机必读）

打开设备后先 `libusb_get_configuration()`；若**已配置（=1）不得再调用
`libusb_set_configuration()`**。Linux usbfs 对已配置设备重复 `SET_CONFIGURATION` 会先
`usb_disable_device(dev,1)`，而本设备无内核驱动、xHCI 端点不会重建，导致 EP1 传输
永久 `LIBUSB_ERROR_IO`（须复位/重枚举恢复）。参考工具已按此实现（"F1a" 规避），
复现脚本 `tools/setcfg_regression.py`。

---

## 2. 数据通路分层

| 通道 | 方向 | 载体 | 用途 |
|---|---|---|---|
| 命令面 | PC→FPGA | EP1 OUT，16 B 命令包 | 复位/使能/测速/配置/统计 |
| 下行批量 | PC→FPGA | EP1 OUT，4+N words 块 | 批量数据下行（测试/未来注入）|
| 上行块 | FPGA→PC | EP1 IN，4+N words 块 | 捕获字节流、ACK |
| 回环 echo | PC→FPGA→PC | 复用上两通道 | 端到端逐字校验（自测）|

---

## 3. 命令面（PC → FPGA）

### 3.1 命令包格式（固定 16 B = 4 × u32 LE）

| word | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'hC7F3}` | 高半字 CRC-16/CCITT-FALSE(W1..W3)，低半字魔数 |
| w1 | `{16'h0, cmd_seq[7:0], cmd_id[7:0]}` | cmd_id ≤ 0x7F；cmd_seq PC 侧自增（FPGA 不校验）|
| w2 | `param[31:0]` | 命令参数 |
| w3 | `{20'h0, payload_len[11:0]}` | 附加数据字数，**当前恒 0**（未实现附加流）|

- CRC 输入为 W1..W3 的**线上字节序共 12 B**（每字小端）；算法对齐
  `uhsif.v crc16_hdr` / `uhsif.h uhsif_hdr_crc16`。
- FPGA 一次 32 位比较判定整头；**非法命令静默丢弃、不回 ACK**。

### 3.2 命令集（串行模型：一次一条，等 ACK 再发下一条）

| cmd_id | 名称 | param | 动作 |
|---|---|---|---|
| 0x01 | FPGA_RESET | 0/1 | ctrl bit0，捕获引擎复位 |
| 0x02 | CAPTURE_ENABLE | 0/1 | ctrl bit1，capturing（兼作上行门控）|
| 0x03 | CAPTURE_SPEED | 0=LS 1=FS 2=HS 3=AUTO | ctrl bit2:3 |
| 0x04 | TEST_MODE | 0/1 | ctrl bit4，计数器全速测试（绕开门控）|
| 0x20 | SET_UPLOAD_PARAMS | 1..4092 | 设置满块阈值 `max_payload_dwords`（默认 1024 words）|
| 0x21 | SET_CHANNEL_MASK | bit0=ULPI | 通道掩码（默认 bit0）|
| 0x22 | SET_BULK_CFG | 见 §7 | 下行/回环调试配置 |
| 0x23 | GET_STATS | 索引 0..15 | 读 FPGA 计数器 |

### 3.3 启动时序（插件固定顺序）

| 步骤 | 命令 | 参数 |
|---|---|---|
| 1 | CAPTURE_ENABLE | 0 |
| 2 | FPGA_RESET | 1 |
| 3 | CAPTURE_SPEED | speed |
| 4 | FPGA_RESET | 0 |
| 5 | CAPTURE_ENABLE | 1 |

每步等待 ACK：发命令 → **200 ms** 内收到任意 ACK 块即成功；超时重发，最多 **3** 次；
重试前若流中出现 ACK 按成功处理（避免重复执行）。

---

## 4. 下行批量通道（PC → FPGA）

### 4.1 块格式

| word | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'hC7F3}` | 同命令块，覆盖 W1..W3 |
| w1 | `{stream_id[7:0], blk_seq[7:0], 8'h30}` | cmd_id=0x30（0x30..0x3F 为下行流保留），blk_seq 每流自增 |
| w2 | `{29'h0, ack_req, last, 1'b0}` | bit0=last，bit1=ack_req（调试）|
| w3 | `{20'h0, payload_len[11:0]}` | payload 字数 N，**1..4092**（位于 w3[11:0]）|
| w4.. | `payload[N]` | 任意数据，LE word 流 |

- 单块总长 = `16 + 4N` 字节，**≤ 16384 B = 16 KiB**（正好一个 UHSIF line 缓冲）。
- FPGA 接收：移位窗口同时满足"魔数 + CRC + 长度>0"即判定为批量块并锁存头部，随后
  按 N 消费 payload；**CRC 非法的头按非法命令丢弃**（主机须发 CRC 正确的块，否则可能
  流失步，用 `blk_seq` 重同步）。
- 块尾由 **AE# / 计数**终止（`stop_lead` 可调，默认 0）；单次读有上限与看门狗，
  绝不读超传输长度。
- 默认**不回 ACK**（USB OUT NAK 背压保证无损）；`w2.bit1` 或 `0x22 ack_en` 可要求回 ACK。

### 4.2 长度与粒度约束

1. payload 按**字节 4 对齐**；
2. payload 范围 **4..4092 words = 16..16368 字节**（工具实用下限 16 B；协议下界为 N≥1）；
3. **一个批量块 = 一次主机 bulk 写（SS）/一个 512 B USB 包（HS）= 一次 UHSIF line1
   传输**，不跨传输；跨传输块（Mode B）未实现；
4. **务必保持"一块 = 一次写入"**：若一次主机写入内含多块，H417 传输内块尾靠计数早停
   （中途撤 RD#）会丢字——这是 2026-09-11 已定位并修复的小块丢字根因。
5. HS 下 payload 建议 ≤504 B。

---

## 5. 上行块通道（FPGA → PC）

### 5.1 块格式（4 words 头 + N words payload，首尾相连无分隔符）

| word | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'h6CC6}` | 高半字 CRC-16/CCITT-FALSE(W1..W3)，低半字魔数 |
| w1 | `{20'h0, channel_mask[11:0]}` | bit0 = ULPI 捕获通道（默认 1）|
| w2 | `{12'h0, test, capturing, speed[1:0], 11'h0, VER[4:0]}` | VER=**3**；speed 0=LS 1=FS 2=HS 3=AUTO |
| w3 | `{seq[7:0], payload_len[11:0], tx_hdr3[11:0]=0}` | **payload_len 位于 w3[23:12]**；seq 位于 w3[31:24] |

- `payload_len == 0` ⇒ **ACK 块**（16 B，无 payload）。
- `1 ≤ payload_len ≤ 4092` ⇒ **数据块，无下限**（v1/LA 的 120 字下限已废弃）。
- `seq` 为 FPGA 每发一块递增（ACK 与数据块共用，8-bit 回绕），PC 侧做连续性校验。
- 单块 ≤ `4+4092 = 4096 words = 16 KiB`。

### 5.2 流控与上报策略（满块优先 + 超时兜底）

- **满块**：`fifo_count ≥ max_payload_dwords`（默认 **1024 words = 4 KiB**）时立即上传整块；
- **短块**：有数据但超过 **10 ms** 仍不足满块，则以当前残余字数（1..4092）上发短块，
  保证低速业务（IN/NAK/SOF、少量控制传输）也能约 100 Hz 刷新；
- **冲刷**：`capturing`/`test` 撤销后把 FIFO 残余以短块刷空。
- PC 侧持续异步批量读，无背压。

> 注：10 ms 超时计数按 125 MHz 配置，实际 UHSIF 时钟 118.18 MHz ⇒ 实际约 **10.6 ms**。

### 5.3 payload = 捕获字节流

payload 字节按 LE word 顺序连续拼接，即捕获引擎产出的**逐字节流**；块边界可能落在
任意捕获帧中间，PC 端按字节流切帧，不依赖块对齐。帧格式见 `protocol.md` §4。

---

## 6. 回环（echo）

- **使能**：`0x22 SET_BULK_CFG` **bit20 = 1**（注意不是 bit16，bit16 与 `rd_cap` 位域重叠）。
- **数据流**：下行批量块 → `rx_stream_*` sink → **echo FIFO** → 上行源（`bulk_echo_en`
  时上行只取 echo FIFO，忽略采集 FIFO，避免半途换源）；回传块的 N 与下发一致。
- **echo FIFO**：**8192 words（AW=13，32 KiB）**。余量不足一个最大块（4084 words）时
  暂停 RX 起读 → 对 line1 反压；因单次最多再涨 4092，FIFO **永不满**，从根上消除核心
  skid 溢出丢字。
- **BRAM 约束**：AW=14 会导致布局失败，故 echo FIFO 上限为 8192 words。
- **能力**：payload **16 B..16368 B** 全长度逐字校验通过（见 §9 基线）。

---

## 7. 调试 / 统计命令

### 7.1 `0x22 SET_BULK_CFG`（param 位域）

| 位 | 名称 | 说明 |
|---|---|---|
| [0] | ack_en | 全局要求下行块回普通 ACK |
| [3:1] | push_lead | payload 推入 sink 的提前拍数（默认 0）|
| [7:4] | stop_lead | 计数读提前停止拍数（默认 0，已与真机一致）|
| [15:8] | arb_words | 预留 |
| [19:16] | rd_cap | 单次读绝对拍数上限（0=关）|
| **[20]** | **echo_en** | **回环使能** |

### 7.2 `0x23 GET_STATS`（索引 0..15，应答 `w2=value`、`w3[11:0]=index`）

| 索引 | 含义 |
|---|---|
| 0 | rx_words（含丢弃）|
| 1 | rx_blocks |
| 2 | rx_dropped |
| 3 | rx_err |
| 4 | rx_last_len |
| 5 | rx_sum（投递 payload 字 32 位加和，用于内容校验）|
| 6 | rx_hdr_cyc（头部检出拍）|
| 7 / 8 | magic / CRC 命中拍数（诊断）|
| 9 | 上次读停止拍数 |

主机用 `rx_sum` 增量与期望图案加和比对即可验证内容。

---

## 8. 使用限制汇总

| 项目 | 限制 | 原因 / 备注 |
|---|---|---|
| 单块总长 | ≤ 16 KiB（4096 words）| 一个 UHSIF line 缓冲；USBSS 每 16 KiB 分链 |
| 下行 payload | 4..4092 words（16..16368 B），4 对齐 | N≥1；工具实用下限 16 B |
| 下行粒度 | **一块 = 一次主机写入（一次传输）** | 多块合写会因计数早停撤 RD# 丢字 |
| 跨传输块 | 未实现（Mode B）| — |
| 上行 payload | 1..4092 words，**无下限** | v1 的 120 字下限已废弃 |
| 上行满块阈值 | 1..4092 words，默认 1024 | `0x20`；见下条回环注意 |
| 回环 payload | 16..16368 B（与下行同）| 受 echo FIFO 8192 words 约束 |
| echo FIFO | 8192 words（AW=13）| AW=14 布局失败；余量 <4084 反压 |
| 回环 + 采集并发 | 不支持（echo 独占上行源）| `bulk_echo_en` 时忽略采集 FIFO |
| **回环时 `0x20`** | 必须 **< echo 反压门限** | 否则只能靠 10 ms 超时聚合，回传显著变慢 |
| HS 模式块 | payload 建议 ≤504 B | 一个 512 B USB 包 |
| 命令模型 | 串行，等 ACK | 批量块与命令不并发下发 |
| 设备长跑 | 多次背压实验后需软复位 | 累积拥塞会导致假失败 |

---

## 9. 性能测试使用说明

### 9.1 构建

```sh
cd extcap.usb_sniffer2
make tools/uhsif_bulk        # -> tools/uhsif_bulk
```

### 9.2 前置条件

- 已安装 udev 规则（`sudo make udev`）或具备对 `1209:6688` 的访问权限；
- 设备运行 **Slot B** 固件且 FPGA 码流与协议 v2.3 匹配（上行块头 VER=3）；
- 长跑/多次实验前先软复位，避免累积拥塞：
  ```sh
  ./tools/uhsif_bulk --cmd 0x01 --param 1     # 或 python3 usb3.ch32h417/Host/IAP/tools/iap_cli.py reset
  ```

### 9.3 命令速查

| 目的 | 命令 | 判定 |
|---|---|---|
| 命令面探活 | `./tools/uhsif_bulk --probe` | `4/4 commands acknowledged` |
| 读协议版本 | `./tools/uhsif_bulk --ver` | VER=3 支持批量通道 |
| 单块下发 | `./tools/uhsif_bulk --send <words>` | 无报错；`--diag` 可 dump rx 统计 |
| 单块诊断 | `./tools/uhsif_bulk --diag <words>` | 打印 rx_blocks/rx_words/rx_sum 等 |
| 下行速率 | `./tools/uhsif_bulk --rate-down --seconds 3 --verify` | `errors=0`、`PASS` |
| 上行速率 | `./tools/uhsif_bulk --rate-up --seconds 3` | `errors=0` |
| 双向并发 | `./tools/uhsif_bulk --rate-concurrent --seconds 3 --verify` | 双向 `errors=0/0`、verify OK |
| 回环速率 | `./tools/uhsif_bulk --rate-loop --seconds 3 --verify` | echo `mism=0/dropped=0` |
| 回环长度扫描 | `./tools/uhsif_bulk --loop-sweep --loop-lens 256-16368 --loop-step 512 --loop-ms 200` | `N/N pass`、`mism=0` |
| 读统计量 | `./tools/uhsif_bulk --stats <idx>` | 返回 `w2` 值 |

> `--send` / `--diag` 的长度单位是 **payload 字数**（4092 = 16 KiB）。
> `--loop-lens` 单位是**字节**，支持 `N`、`A-B`（步长由 `--loop-step` 控制，默认 4）与逗号列表。

### 9.4 常用参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--seconds <n>` | 5 | 速率测试时长 |
| `--depth <n>` | 8 | 异步 URB 并发深度 |
| `--xfer-size <bytes>` | 262144 | 传输缓冲大小 |
| `--pattern counter\|prbs` | counter | 校验图案（`--verify` 时比对）|
| `--verify` | 关 | 独立核心做逐字内容校验 |
| `--echo` | 关 | 使能 echo sink 并校验 payload |
| `--loop-window <words>` | 0 | 限制回环在途字数；0=全速（靠 RTL 反压），调试可设 <4096 |
| `--recover` | 关 | 退出时软复位设备 |

### 9.5 参考基线（2026-09-11 真机，`--seconds 3`）

| 测试 | 命令 | 结果 |
|---|---|---|
| 上行 | `--rate-up` | **418.6 MB/s**，`errors=0` |
| 下行 | `--rate-down --verify` | **409.1 MB/s**，`errors=0`，校验 PASS |
| 双向并发 | `--rate-concurrent --verify` | down **236.4** + up **236.5** = **472.9 MB/s**，`errors=0/0`，`mism=0` |
| 回环 | `--rate-loop --verify` | down **236.3** + up **236.2** = **472.5 MB/s**，`mism=0/dropped=0` |

回环长度扫描（`--loop-ms 150`，step 512）：**256..16128 B 全部 PASS**；逐字校验
`mism=0 / badhdr=0 / dropped=0 / io=0`。小块带宽随块增大上升（256 B≈19、1 KB≈59、
4 KB≈133、16 KB≈176 MB/s），小块仅受每块/URB 开销限制，非功能限制。

### 9.6 结果判读

- `errors=0` / `errors=0/0`：主机侧传输无 `LIBUSB_ERROR`；
- `PASS`：`consumed` 与 `expected` 在收尾误差内一致、无 badhdr/dropped；
- 回环 `--verify`：`mism=0 bad_hdr=0 dropped=0` 为逐字校验通过；
- `GET_STATS(x): no matching reply` 偶发为读统计与数据/ACK 流的竞态，**不影响**当次
  PASS 判定（速率测试自身以其计数为准）。

### 9.7 故障排查

| 现象 | 排查 |
|---|---|
| `--probe` 无 ACK | 固件/码流版本不匹配（需 VER=3）；或设备已 wedge，软复位/重插 |
| EP1 传输 `LIBUSB_ERROR_IO` | 主机侧 F1a 违规（重复 SET_CONFIGURATION）；复位设备 |
| 小块回环丢字 | 检查是否保持了"一块=一次写入"；勿把多块拼进一次写入 |
| 回环速率异常低 | `0x20` 满块阈值须小于 echo 反压门限；或先用 `--recover` 清拥塞 |
| 长跑后突然失败 | 累积拥塞，软复位设备后重测 |
| 上行无数据/停滞 | 固件上行计数只增不减（WCH 例程限制）；会话收尾软复位 |

---

## 10. 版本门控与兼容性

- 上行块头 `w2[4:0] VER=3` 表示支持下行批量通道；主机读到 **VER<3 必须禁用批量功能**。
- `VER=2` 及以前为纯命令面，行为与 v2.2 完全一致；命令面与上行块格式自 v2.2 起
  **完全不变**，v2.3 仅新增批量通道与 `0x22/0x23`。
- v2.2 起头校验为 **CRC-16/CCITT-FALSE**；命令魔数 `0xC7F3`、块魔数 `0x6CC6`。
