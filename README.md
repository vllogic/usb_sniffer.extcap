# USB Sniffer — Wireshark extcap 插件（两代合一）

一个二进制、一个捕获接口，自动支持两代 USB 协议分析仪的实时 LS/FS/HS 总线捕获，
输出 pcapng 供 Wireshark 解析。接口注册值 `value=usb_sniffer`（接口列表中显示为
"Vllogic"，extcap 版本 2.0）：

| 硬件 | VID:PID + bcdDevice | 数据路径 |
|---|---|---|
| gen1: ataradov USB Sniffer（FX2LP + Lattice FPGA） | 1209:6688 rev 0x0001；legacy 6666:6620；FX2LP 引导 04b4:8613 | EP 0x82 原始帧流 + EP0 vendor 控制 |
| gen2: Vllogic USB Sniffer 2（CH32H417 + UHSIF 链路） | 1209:6688 rev 0x0602 | EP1 IN/OUT + UHSIF 4-word 块协议 |

两代共享同一 VID:PID，以设备描述符的 bcdDevice 区分，互不误认。
启动捕获前 `device_probe()` 扫描总线（`src/device.c`）选择引擎：

- 两代同时接入：报错 `both capture generations are connected; unplug one of them`；
- 只检测到未配置 FX2LP（04b4:8613）：提示先加载固件（`--mcu-sram`/`--mcu-eeprom`），
  或拔掉无关的 FX2LP 设备。

gen1 额外保留上游维护工具（`--mcu-sram/--mcu-eeprom/--fpga-sram/
--fpga-flash/--fpga-erase`）与 `--test` 速率测试；gen2 保留离线回放
`--replay`（无硬件验证用）。

## 构建

支持 Linux / macOS / Windows(MSYS2/MinGW) 三平台，统一由 Makefile 驱动：

```sh
make            # 生成 capture_usb_vllogic (Linux/macOS) 或 capture_usb_vllogic.exe (Windows)
make install    # 安装到 Wireshark extcap 目录
sudo make udev  # (仅 Linux) 安装 udev 规则，重插设备生效
```

### Linux

```sh
sudo apt install gcc make pkg-config libusb-1.0-0-dev
make            # -> capture_usb_vllogic
make install    # -> ~/.local/lib/wireshark/extcap/
sudo make udev  # 免 root 访问: 04b4:8613 (FX2LP引导), 6666:6620 (legacy), 1209:6688 (两代)
```

### macOS

```sh
brew install libusb pkg-config
make && make install
```

### Windows（MSYS2/MinGW64）

一键脚本（在 **MSYS2 MINGW64** 终端、仓库根目录执行，非 MSYS 终端）：

```sh
bash tools/build-msys2.sh
```

脚本自动安装 `mingw-w64-x86_64-{gcc,make,pkgconf,libusb}` 并构建
`capture_usb_vllogic.exe`，拷入 `%APPDATA%\Wireshark\extcap\` 后重启 Wireshark
刷新接口列表。

> 说明：插件在 Windows 下启动时强制将 stdout/stderr 设为二进制模式
> （`_setmode(...,_O_BINARY)`），避免 CRT 文本模式把 `\n` 转成 `\r\n` 破坏
> extcap 协议流（fifo/dlt/arg 行污染）。该处理位于 `src/main.c`。

## 用法

Wireshark 中刷新接口列表即出现 "Vllogic"（自动探测硬件）；
或用命令行：

```sh
./capture_usb_vllogic --capture --fifo /tmp/cap.pcapng --speed auto --fold   # 自动探测硬件
./capture_usb_vllogic --help
```

参数（定义见 `src/extcap.c`）：

- `-s, --speed {auto,ls,fs,hs}`（默认 auto）
- `-l, --fold`、`-e, --exclude`、`-n, --limit N`（0=不限）
- `-t, --trigger {disabled,low,high,falling,rising}`
- `--test`（gen1 传输速率测试）
- extcap 标准参数：`--extcap-{interfaces,interface,dlts,config,version,capture}`、`-f/--fifo`
- gen1 维护参数与 `--replay`（gen2 离线回放）

DLT 映射由 `dlt_for_speed()` 决定：`ls→293`、`fs→294`、`hs→295`、`auto→288`；
`--extcap-dlts` 会同时通告 288/293/294/295 四种 USB 链路类型。

调试日志重定向：`USB_SNIFFER_LOG=/path/log.txt`（live 捕获时 stderr 日志
被静默，重定向文件仍会记录）。

### gen1 固件/FPGA 工具（需接 gen1 硬件，文件路径对应 ataradov 仓库布局）

```sh
./capture_usb_vllogic --mcu-sram   ../firmware/usb_sniffer.bin    # FX2LP SRAM 直载运行
./capture_usb_vllogic --mcu-eeprom ../firmware/usb_sniffer.bin    # 写入 EEPROM（含 SN）
./capture_usb_vllogic --fpga-sram  ../fpga/impl/usb_sniffer_impl.bit
./capture_usb_vllogic --fpga-flash ../fpga/impl/usb_sniffer_impl.jed
./capture_usb_vllogic --fpga-erase
./capture_usb_vllogic --test                                       # 传输速率测试
```

## gen2 启动/收尾时序（`src/main.c`、`src/transport_libusb.c`）

每次实时会话按下列顺序建立干净链路：

1. **预清理**：静默发送 `ENABLE 0` / `RESET 1` 停住 FPGA，再 `transport_discard()`
   同步排空上一会话（Wireshark 强杀 extcap 进程）残留的上行块，避免旧数据进入管线。
2. **链路带宽探测**（仅实时）：把满块阈值 `0x20 UPLOAD_PARAMS` 调到协议上限
   4092 words（16 KiB），开启 `0x04 TEST` 计数器全速填充约 400 ms，测得上行
   MB/s 后关闭 TEST 并再次排空。测得的速率作为第一条 UPPER_PDU 信息写入 pcapng
   （`Link bandwidth (uplink): N MB/s`）。16 KiB 块相比 FPGA 上电默认的 4 KiB
   显著提升上行吞吐（真机 SuperSpeed 实测约 91 → 418 MB/s）。
3. **带 ACK 初始化**：`UPLOAD_PARAMS=4092` → `SPEED=speed` → `RESET=0` →
   `ENABLE=1`，逐条等待 ACK（200 ms 超时；最多重发 3 次，重试前若流中已出现
   ACK 则按成功处理，避免命令被重复执行）。若首条命令始终无 ACK（Windows 重启后
   EP1 IN 可能僵死），软复位设备一次（EP0 vendor request 0xE2）并重开传输后
   重试整个序列。
4. 写入 pcapng 骨架与 `Starting capture`/`Waiting for a trigger` 信息后，才切换到
   异步流模式（此前命令面用同步读解析 ACK）。

会话结束（用户 Stop / 信号 / 抓满）：先带应答发送 `ENABLE 0`（失败则异步补发）
关闭 FPGA 捕获（否则板载 RGB 会持续按速率闪烁），再关闭传输；`tl_close()` 末尾
再补一次 vendor 0xE2 软复位，抵消 CH32 上行计数只增不减导致的 EP1 停滞。

## 离线回放（gen2，无硬件验证）

```sh
python3 tools/make_fake_stream.py --speed ls --in <样本.pcapng> --out test.bin
./capture_usb_vllogic --replay test.bin --fifo out.pcapng --speed ls --fold
```

回放传输（`src/transport_replay.c`）按文件中的预录 UHSIF 块流模拟命令阶段
（每 pump 一个 16 字节 ACK 块）与数据阶段（4 KiB 分块），命令面初始化的 5 个 ACK
由 `make_fake_stream.py` 生成。

## 测试

```sh
make test SAMPLE_DIR=/path/to/ref.ataradov.usb-sniffer/doc
```

等价于 `test-ls` + `test-fs` + `test-hs` + `test-features`：

- 3 样本回归（LS/FS/HS）：`make_fake_stream.py` 把参考 pcapng 转成 UHSIF 流，
  插件 `--replay` 复现后由 `check_pcapng.py` 比对参考抓包；
- 功能自洽测试（`tools/feature_tests.py`）：折叠空帧、LS keep-alive、触发门控、
  抓包上限、硬件缓冲溢出、周期刷新等。

均需 python3；`SAMPLE_DIR` 默认指向本机 ataradov 仓库的 `doc/`，不存在时
`sample-check` 会给出提示。

## 设备状态说明

- gen2 的 UHSIF 上行计数在固件侧只增不减（WCH 例程未实现中断回调链），
  多次连续捕获会话后会 EP1 停滞。插件已在会话收尾自动软复位设备
  （vendor request 0xE2，等价 `iap_cli.py reset`），下一次会话可直接
  运行；`tl_open` 带 5s 重试以容忍复位后的设备重枚举窗口。
- Windows 重启后若首条命令无 ACK，插件会自动软复位并重试一次；若仍失败，
  先 `python3 usb3.ch32h417/Host/IAP/tools/iap_cli.py reset` 再试。
- gen2 固件需配合正确版本 FPGA 码流（`gens/h7p20.builtin-4c22c79.lr4.bin`），
  旧码流（`9b55e8a.lr4.bin`）会使 UHSIF 命令面无 ACK。
- gen2 在 USB2 母口下同样工作（2.0 落地态固件走 USBHS 数据面，EP1 直连
  UHSIF，仅速率上限受 USB2 HS bulk 约束）。
- gen1 未配置时是 FX2LP 默认引导设备（04b4:8613），用 `--mcu-sram` 直载
  固件即可运行；`--mcu-eeprom` 则永久写入。

## 文档

- [`docs/protocol.md`](docs/protocol.md)：UHSIF 字节级协议定义（命令面 / 上下行块格式）。
- [`docs/uhsif_interface.md`](docs/uhsif_interface.md)：UHSIF v2.3 接口技术说明、使用限制与
  性能测试使用指南（含真机基线数据与 `tools/uhsif_bulk` 用法）。

## 源码结构

- 入口/公共层：`main.c`（引擎分发、gen2 启动/收尾时序、gen1 维护入口）、
  `os_common.*`（类型/日志/文件/PRNG）、`extcap.*`（选项与单接口）、
  `capture_defs.h`（speed/trigger 枚举）、`device.*`（VID/PID/bcdDevice 探针）、
  `uhsif.h`（协议常量与 CRC-16）、`pcapng.*`（写器）、`packet.*`
  （帧解析 + interpret，移植自 gen1 capture.c）。
- gen2：`stream.*`（UHSIF 块切分/魔数+CRC 同步/seq 校验）、`cmd.*`（命令/ACK/重试）、
  `transport.c` + `transport_libusb.c`（实时 libusb）+ `transport_replay.c`（离线回放）、
  `transport_internal.h`。
- gen1：`gen1/usb.*`（libusb 后端+维护通道）、`gen1/capture.*`（捕获引擎）、
  `gen1/fx2lp.*`、`gen1/fpga.*`（固件/码流编程，与上游保持一致）。

## 工具（`tools/`）

- `build-msys2.sh`：Windows（MSYS2/MinGW64）一键构建。
- `make_fake_stream.py` / `check_pcapng.py` / `feature_tests.py`：离线回归套件。
- `uhsif_bulk.c`：UHSIF v2.3 下行批量/回环/上下行测速标定工具，
  `make tools/uhsif_bulk` 单独构建（不参与插件本体）。
- `setcfg_regression.py`、`uhsif_capture.py`、`uhsif_loopback_test.py`、`usb_cmd.c`：
  设备/协议辅助与复现脚本。
