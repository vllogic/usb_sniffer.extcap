# USB Sniffer 2 插件协议文档（v2 · FPGA 侧定稿）

本文档是 `usb_sniffer2` 上位机（Wireshark extcap 插件 / CH32H417 固件）与
FPGA（H7P20）之间链路的**字节级协议定义**，以 FPGA 侧实现
（`fpga.h7p20/src/uhsif.v` + `uhsif_usbsniffer.v`）为基准。

> 版本历史：v1 为逻辑分析仪（LA）兼容协议；v2 为 usb_sniffer2 专用协议，
> 命令面与上行块头均重新定义；**v2.2**：头校验由折叠 XOR 升级为
> CRC-16/CCITT-FALSE，命令魔数 `0x5AA5` → `0xC7F3`（块魔数 `0x6CC6` 不变），
> 布局 `{crc16, magic}` 与 v2.1 相同。**上位机代码（`cmd.c` 打包、
> `stream.c` 解析）需按本文档 v2.2 同步调整，本版为 FPGA 侧已经实现的定稿。**
> **v2.3（2026-09-10，真机验证通过）**：新增下行批量通道（§2A）、
> `0x22/0x23` 调试命令，上行块头 `VER` 2→3；命令面与上行块格式**完全不变**。
> 2026-09-11 补充：批量块长度范围放开为 **16..16368 字节**（原 8192 下限取消），
> 约束为"一个块 = 一次主机写入（AE# 收尾）"；16B..16KB 回环逐字校验已全 PASS。

## 1. 传输拓扑

```
PC ──EP1 OUT(16B 命令包)──▶ CH32H417(DMA 透传) ──UHSIF L1──▶ FPGA
PC ◀──EP1 IN(4+N words 块)── CH32H417(DMA 透传) ◀──UHSIF L0── FPGA
```

- 设备为 vendor class，端点 EP1 IN(0x81) / EP1 OUT(0x01)；USB3 SuperSpeed 下为
  bulk 1024B×burst 15；USB2 HS 512B 逐包泵同样直连 UHSIF（固件 `usb_data_path`
  在 2.0 落地态切到 USBHS，EP1 IN 由固件按 512B 分片消费 line0，EP1 OUT 直通
  line1 命令面；链路速率上限按 USB2 HS bulk 而定）。
- 固件（CH32）对上/下行内容零语义整包透传，无封装、无校验、无改动。
- UHSIF 接口时钟实测口径 118 MHz（PLL `pll_fixed.v` 实际输出，顶层注释
  118.18 MHz），非标称 125 MHz；10 ms 短块超时计数按 125 M 配置，实际约 10.6 ms。
- 字节序：**全 little-endian**。UHSIF 32-bit word 的低字节 = 先到达 USB 的字节。
- VID/PID：`0x1209 / 0x6688`（固件 `usb_desc.h` 与 udev 规则同步）。
- **主机侧强制要求（第三方上位机必读）**：打开设备后先 `libusb_get_configuration()`，
  已配置（=1）时**不得**再调用 `libusb_set_configuration()`/SET_CONFIGURATION。
  Linux 内核对"已配置设备"的重复 `USBDEVFS_SETCONFIGURATION` 会先执行
  `usb_disable_device(dev, 1)`，而本设备为无内核驱动的 vendor 接口，xHCI 端点不会
  被重建，导致其后 EP1 bulk 传输永久 `LIBUSB_ERROR_IO`（须设备复位/重枚举恢复）。
  设备固件本身对 wire 级 SET_CONFIGURATION 处理正常，问题在主机 usbfs/内核路径；
  各参考工具已按此规则实现（F1a），复现/验收脚本：
  `tools/setcfg_regression.py`，背景见 `docs/tasks/set_configuration_ep1_wedge.md`。

## 2. 命令面（PC → FPGA，EP1 OUT）

固定 `16 字节 = 4 × u32 LE`：

| 偏移(word) | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'hC7F3}` | 高半字为**头校验（CRC-16/CCITT-FALSE）**；低半字魔数 |
| w1 | `{16'h0, cmd_seq[7:0], cmd_id[7:0]}` | cmd_id ≤ 0x7F；cmd_seq 为 PC 侧命令序号（FPGA 仅透传，不校验） |
| w2 | `param[31:0]` | 命令参数 |
| w3 | `{20'h0, payload_len[11:0]}` | 附加数据字数（当前恒 0，未实现附加数据流） |

- `crc16 = CRC-16/CCITT-FALSE(W1,W2,W3)`：多项式 `0x1021`、初值 `0xFFFF`、
  字节内 MSB 先行、不反演、无最终异或；输入为 **W1,W2,W3 的线上字节序
  （每字小端）共 12 字节**（与块头侧对称，见 §3）。检错能力：全部 ≤16 bit
  突发错误、全部奇数位错误，以及 v2.1 折叠 XOR 漏检的同位对称双位错误。
  实现对齐：`uhsif.v` `crc16_hdr`（并行矩阵）、`uhsif.h` `uhsif_hdr_crc16`、
  `tools/` 各脚本/工具逐字节一致。
- FPGA 判定（`uhsif.v` S_RX_PROCESS）：`W0 == {crc16, 16'hC7F3}`（一次 32 位
  比较）；**非法命令静默丢弃、不产生 ACK**。

### 命令集（串行模型：一次一条，等 ACK 再发下一条）

| cmd_id | 命令 | param | FPGA 侧动作（`uhsif_usbsniffer.v`） | 对应老插件 |
|---|---|---|---|---|
| 0x01 | FPGA_RESET | 0/1 | 置 ctrl bit0（捕获引擎复位，高有效） | Reset |
| 0x02 | CAPTURE_ENABLE | 0/1 | 置 ctrl bit1（capturing，同时作为上行门控） | Enable |
| 0x03 | CAPTURE_SPEED | 0=LS 1=FS 2=HS 3=AUTO | 置 ctrl bit2:3 | Speed0/Speed1 |
| 0x04 | TEST_MODE | 0/1 | 置 ctrl bit4（计数器全速测试，绕开门控） | Test |

> 预留：`0x20 SET_UPLOAD_PARAMS`（调整 `max_payload_dwords`（满块阈值），默认 1024，
> 合法域 1..4092——值越小满块越频繁，一般无需调整）、`0x21 SET_CHANNEL_MASK`
> （默认 bit0=ULPI 通道）——FPGA 已实现，首版插件可不发送。

### 启动时序（插件固定顺序）

| 步骤 | 命令 | 参数 |
|---|---|---|
| 1 | 0x02 CAPTURE_ENABLE | 0 |
| 2 | 0x01 FPGA_RESET | 1 |
| 3 | 0x03 CAPTURE_SPEED | speed |
| 4 | 0x01 FPGA_RESET | 0 |
| 5 | 0x02 CAPTURE_ENABLE | 1 |

每步等待 ACK：发命令 → 200 ms 内收到任意 ACK 块即成功；超时重发（最多 3 次）；
重试前若流中出现 ACK 按成功处理（避免命令被重复执行）。

## 2A. 下行批量通道（v2.3，真机验证通过）

FPGA 在命令面之外新增一条 PC→FPGA 的批量数据通道，复用同一 EP1 OUT / UHSIF
line1；命令与批量块**串行发送**（批量块默认不回 ACK）。

### 批量块格式

| word | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'hC7F3}` | 同命令块，覆盖 W1..W3 的 CRC-16/CCITT-FALSE |
| w1 | `{stream_id[7:0], blk_seq[7:0], 8'h30}` | cmd_id=0x30（`0x30..0x3F` 为下行流保留）；blk_seq 每流递增 |
| w2 | `{29'h0, ack_req, last, 1'b0}` | bit0=last，bit1=ack_req（调试：要求回 ACK），其余保留 0 |
| w3 | `{20'h0, payload_len[11:0]}` | payload 字数 N，1..4092 |
| w4.. | payload[N] | 任意数据，LE word 流 |

- 单块最大 `4+4092 = 4096 words = 16 KiB`，正好一个 UHSIF line1 缓冲。
- **长度约束（v2.3）**：
  1) payload 长度按**字节 4 字节对齐**；
  2) **单块 payload 范围 16..16368 字节**（4..4092 words）。实测 16B..16KB 全长度
     回环逐字校验零错误；带宽随块增大上升（256B≈19MB/s、4KB≈133MB/s、16KB≈176MB/s），
     小块仅受每块/URB 开销限制，非功能限制；
  3) **一个批量块 = 一次主机 bulk 写（SS）/一个 512B USB 包（HS）**，即一次 UHSIF
     line1 传输（不跨传输；跨传输块未实现）。一个主机写入若含多块，H417 传输内块尾
     靠计数早停会中途撤 RD# 而丢字——务必保持"一块=一次写入"；
  4) HS 下块 payload 建议 ≤504B（一个 512B USB 包）。
- FPGA 接收规则：移位窗口同时满足"魔数+CRC+长度>0"即判定为批量块并锁存头部；
  随后按 N 消费 payload 推入 `rx_stream_*` sink；**CRC 非法的头按非法命令丢弃**
  （主机必须发 CRC 正确的块，否则可能流失步，用 `blk_seq` 重同步）。
- 块尾由 AE#/计数终止（`stop_lead` 可调，默认 0 已与真机一致）；单次读有上限
  与看门狗，绝不读超传输长度。
- 默认不回 ACK（USB OUT 的固件 NAK 背压保证无损）；`w2.bit1` 或 `0x22 ack_en`
  可要求回普通 ACK（调试/标定）。
- **传输粒度约束**：一个批量块 = 一次 UHSIF line1 传输（SS：一次主机 bulk 写；
  HS：一个 512B USB 包）。大块（≤16KB）实测可用；跨传输块（Mode B）未实现。

### 命令扩展（0x22/0x23，调试/标定）

| cmd_id | 命令 | param | 应答 |
|---|---|---|---|
| 0x22 | SET_BULK_CFG | `[0]=ack_en, [3:1]=push_lead, [7:4]=stop_lead, [15:8]=arb_words(预留), [19:16]=rd_cap, [20]=echo_en(回环)` | 普通 ACK |
| 0x23 | GET_STATS | 索引 0..15 | ACK 的 `w2=value`、`w3[11:0]=index` |

GET_STATS 索引：0=rx_words（含丢弃）、1=rx_blocks、2=rx_dropped、3=rx_err、
4=rx_last_len、5=rx_sum（投递 payload 字 32 位加和，用于内容校验）、
6=rx_hdr_cyc（头部检出拍）、7/8=magic/CRC 命中拍数（诊断）、9=上次读停止拍数。
主机用 `rx_sum` 增量与期望图案加和比对即可验证内容（`tools/uhsif_bulk.c` 已实现）。

### 版本门控

上行块头 `w2[4:0] VER=3` 表示支持批量通道；主机读到 VER<3 必须禁用批量功能。
`VER=2` 及以前为纯命令面，行为与 v2.2 完全一致。

### 验证状态（2026-09-10/11 真机）

- 全长度 sweep：len=1..4092，`consumed==N`、`blocks=1`、`rx_sum` 一致、err=0；
  头部检出拍恒为 5（`push_lead=0`）。
- 回环长度扫频（2026-09-11）：payload 16B..16368B（step 512 + 边界 + 1024 倍数）
  全部 PASS，`mism=0`、`dropped=0`、`badhdr=0`、`io=0`，块与写入一一对应。
- 小块回环根因（已修复）：一个批量块拆成多次主机写入时，H417 传输内含多块、块尾
  靠计数早停（中途撤 RD#）会丢字；改为**一个块 = 一次主机写入**（AE# 收尾）后消除。
- 持续流：16KB 块 10000 连发（164MB）零错误，约 82–123 MB/s；
  上下行并发（TEST_MODE 计数流 + 批量下行）双向零错误。
- 已知限制：单块 ≤16KB；HS 跨传输块未实现；批量块与命令串行，不并发下发。

## 3. 上行块格式（FPGA → PC，EP1 IN）

FPGA 按块连续上送，无分隔符，块与块首尾相连。每块 = 头 4 words + 可选 payload N words：

| word | 位域 | 说明 |
|---|---|---|
| w0 | `{crc16[15:0], 16'h6CC6}` | 高半字为头校验（CRC-16/CCITT-FALSE of W1..W3）；低半字魔数 |
| w1 | `{20'h0, channel_mask[11:0]}` | 通道掩码，bit0 = ULPI 捕获通道（默认 1） |
| w2 | `{12'h0, test_mode, capturing, speed[1:0], 11'h0, VER[4:0]}` | 低 5 位为协议版本 `VER=2`；speed = 0 LS / 1 FS / 2 HS / 3 AUTO |
| w3 | `{seq[7:0], payload_len[11:0], 12'h0}` | seq 为块递增号（8-bit）；低 12 位为 payload 字数，bit15:12 保留 |

- `crc16 = CRC-16/CCITT-FALSE(W1,W2,W3)`，与命令面对称（定义见 §2）。
- `payload_len == 0` ⇒ **ACK 块**（16 字节，无 payload），表示上一条命令已被 FPGA 处理。
- `1 ≤ payload_len ≤ 4092` ⇒ **数据块**（**任意长度均合法，无下限**；v1/逻辑分析仪的
  120 字下限对 sniffer2 无意义），w4.. 为 payload words（压缩的捕获字节流）。
- `seq` 为 FPGA 传输块递增号（每发一块 `S_TX_END` 时 +1，ACK 与数据块共用计数，
  8-bit 回绕），用于 PC 侧连续性校验；**与命令面的命令序号无关**。
- 流控与上报策略：FPGA 在捕获中按"满块优先 + 超时兜底"上报——
  - 满块：`fifo_count ≥ max_payload_dwords`（默认 1024 words = 4096 字节）时核心立即上传一整块；
  - 低数据量：捕获中有数据但超过 **10 ms** 仍不足满块时，FPGA 立刻以当前残余字数上发一个短块
    （`1..4092` 任意长度），保证即使低速业务（IN/NAK/SOF、少量控制传输）也能以 ~100 Hz 刷新，
    契合 Wireshark 显示刷新率；
  - 捕获停止：`capturing`/`test` 撤销后 FPGA 进入残余冲刷，把 FIFO 剩余以短块逐块刷空。
  PC 侧持续异步批量读，无背压。

### 数据块 payload = 捕获字节流

payload 字节按 LE word 顺序连续拼接，即上层捕获引擎（`usb_capture` 语义）产出的
**逐字节流**，块边界可能落在任意捕获帧中间，PC 端按字节流切帧，不依赖块对齐。
每个 32-bit word 的字节序：byte0 → `[7:0]`（低字节，先到 USB），byte3 → `[31:24]`。

## 4. 捕获内容格式（帧层解析）

payload 字节流中的捕获帧（与老插件 `capture.c` / FPGA `usb_capture.v` 一致）：

### 4.1 帧头（类型字节 bit7）

- bit7 = 0 ⇒ **状态帧**（4 字节头）；
- bit7 = 1 ⇒ **数据帧**（7 字节头 + payload）。

### 数据帧（7 字节头）

| 字节 | 位域 |
|---|---|
| 0 | `{1, toggle, 0(zero), ts_overflow, ts[19:16]}` |
| 1 | ts[15:8] |
| 2 | ts[7:0] |
| 3 | `{00, data_error, crc_error, overflow, size[10:8]}` |
| 4 | size[7:0] |
| 5 | duration[15:8]（@60MHz，本版不使用） |
| 6 | duration[7:0] |

- `size` = 帧总长（头+载荷），合法 7..1280；载荷长 = size-7。
- 错误标志：`overflow`=0x08、`crc_error`=0x10、`data_error`=0x20。
- 时间戳：20-bit ts @60MHz，ns 换算 `(ts_int | ts) * 100 / 6`；ts 溢出（bit4 置位）
  时 `ts_int += 0x100000`。

### 状态帧（4 字节头）

| 字节 | 位域 |
|---|---|
| 0 | `{0, toggle, 0, ts_overflow, ts[19:16]}` |
| 1-2 | ts[15:0] |
| 3 | `{speed[1:0], trigger, vbus, ls[3:0]}` |

- speed：0=LS 1=FS 2=HS 3=Reset(未知)；trigger/vbus 为 1-bit；ls 4-bit 线状态。

## 5. PC 侧处理流程（本插件）

```
EP1 IN 异步读 ─▶ stream 层（块切分/魔数同步/seq 校验）
                    ├─ ACK 块 ─▶ 命令层（ACK 裁决）
                    └─ 数据块 ─▶ frame 层（字节流切帧）
                                        │
                                        ▼
                              interpret 层（事件/折叠/门控/溢出）
                                        │
                                        ▼
                              pcapng 写入（SHB/IDB/EPB + UPPER_PDU info）
```

- 流同步：先按低半字魔数过滤（`w0[15:0]==0x6CC6`），命中候选再校验高半字
  `crc16`（v2.1 的固定魔数 `0x5AA5` 在 v2.2 退役，命令面改用 `0xC7F3`）；
  按 `payload_len` 前进；头无效或 seq 跳变 ⇒ 重扫描并上报"链路丢包"；
  重同步后连续 ≥2 块无错再确认。
- 块头字段读取位域：`channel_mask=w1[11:0]`、`speed=w2[17:16]`、`capturing=w2[18]`、
  `test=w2[19]`、`VER=w2[4:0]`、`seq=w3[31:24]`、`payload_len=w3[23:12]`。
- 折叠：IN/NAK/SOF 空帧折叠计数（LS/FS 上限 1000、HS 上限 8000）；有错误标志或
  overflow 时先 `stop_folding()` 再落包。
- DLT 映射：`--speed ls→293、fs→294、hs→295、auto→288`；IDB 按该值写入，
  extcap 列表通告 288。
- 信息流：DLT 252 (UPPER_PDU/syslog)，接口 id 1，写事件字符串
  （Starting capture / Trigger input / VBUS / Detected speed / Line state /
  Keep-alive / Folded N empty frames / Hardware buffer overflow /
  Periodic update / 各 Error 等）。

## 6. P3 真机首验核对表

字节序假设（LE）与部件对应关系见图 §1；若 PC 端出现魔数错位，排查顺序：

1. **字节序**：FPGA 打包器若以大端组装 word，则 PC 端按 LE 解包会错位。
2. **打包器边界**：确认捕获引擎字节→word 的填充方式（低字节优先）与块边界。
3. **固件 DMA 链**：确认 UHSIF L0/L1 数据不经过任何字节重排或长度修改。

验证命令闭环：发 Enable0 → 应回 16B ACK（`w0` 低 16 位 = 0x6CC6 且 crc16 校验正确、
`w3` 低 12 位 = 0）且 `w3[31:24]` seq 每次 +1；发 Enable1 后，FIFO 水位达到
`max_payload_dwords` 时上报满块；低速业务（数据到达 10 ms 仍不足满块）上报短块，
无需凑满整包。
