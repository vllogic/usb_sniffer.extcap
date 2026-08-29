# USB Sniffer — Wireshark extcap 插件（两代合一）

一个二进制、一个捕获接口，自动支持两代 USB 协议分析仪的实时 LS/FS/HS 总线捕获，
输出 pcapng 供 Wireshark 解析：

| 硬件 | VID:PID + bcdDevice | 数据路径 |
|---|---|---|
| gen1: ataradov USB Sniffer（FX2LP + Lattice FPGA） | 1209:6688 rev 0x0001；legacy 6666:6620；FX2LP 引导 04b4:8613 | EP 0x82 原始帧流 + EP0 vendor 控制 |
| gen2: Vllogic USB Sniffer 2（CH32H417 + UHSIF 链路） | 1209:6688 rev 0x0602 | EP1 IN/OUT + UHSIF 4-word 块协议 |

两代共享同一 VID:PID，以设备描述符的 bcdDevice 区分，互不误认。
Wireshark 捕获接口列表只显示一个 "USB Sniffer"（`usb_sniffer`），
启动捕获时插件自动探测当前硬件并选择对应引擎；两代同时接入会报错
提示拔掉其一。

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

一键脚本（在 **MSYS2 MINGW64** 终端执行，非 MSYS 终端）：

```sh
bash extcap.usb_sniffer2/tools/build-msys2.sh
```

脚本自动安装 `mingw-w64-x86_64-{gcc,make,pkgconf,libusb}` 并构建
`capture_usb_vllogic.exe`，拷入 `%APPDATA%\Wireshark\extcap\` 后重启 Wireshark
刷新接口列表。

> 说明：插件在 Windows 下启动时强制将 stdout/stderr 设为二进制模式
> （`_setmode(...,_O_BINARY)`），避免 CRT 文本模式把 `\n` 转成 `\r\n` 破坏
> extcap 协议流（fifo/dlt/arg 行污染）。该处理位于 `src/main.c`。

## 用法

Wireshark 中刷新接口列表即出现 "USB Sniffer"（自动探测硬件）；
或用命令行：

```sh
./capture_usb_vllogic --capture --fifo /tmp/cap.pcapng --speed auto --fold   # 自动探测硬件
./capture_usb_vllogic --help
```

参数：`--speed{auto,ls,fs,hs}`、`--fold`、`--exclude`、`--trigger{disabled,low,high,falling,rising}`、
`--limit N`、extcap 标准参数 `--extcap-{interfaces,interface,dlts,config,version,capture,fifo}`，
以及 gen1 维护参数与 `--replay`（gen2 离线回放）。

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

## 离线回放（gen2，无硬件验证）

```sh
python3 tools/make_fake_stream.py --speed ls --in <样本.pcapng> --out test.bin
./capture_usb_vllogic --replay test.bin --fifo out.pcapng --speed ls --fold
```

## 测试

```sh
make test SAMPLE_DIR=/path/to/ref.ataradov.usb-sniffer/doc
```

3 样本回归（LS/FS/HS，比对参考抓包）+ 功能自洽测试（需 python3）。

## 设备状态说明

- gen2 的 UHSIF 上行计数在固件侧只增不减（WCH 例程未实现中断回调链），
  多次连续捕获会话后会 EP1 停滞。插件已在会话收尾自动软复位设备
  （vendor request 0xE2，等价 `iap_cli.py reset`），下一次会话可直接
  运行；`tl_open` 带 5s 重试以容忍复位后的设备重枚举窗口。
- 若手动时序下遇到 `FPGA did not acknowledge`，先 `python3
  usb3.ch32h417/Host/IAP/tools/iap_cli.py reset` 再试。
- gen2 固件需配合正确版本 FPGA 码流（`gens/h7p20.builtin-4c22c79.lr4.bin`），
  旧码流（`9b55e8a.lr4.bin`）会使 UHSIF 命令面无 ACK。
- gen1 未配置时是 FX2LP 默认引导设备（04b4:8613），用 `--mcu-sram` 直载
  固件即可运行；`--mcu-eeprom` 则永久写入。

## 源码结构

- 公共层：`os_common.*`（类型/日志/文件/PRNG）、`extcap.*`（选项与单接口）、
  `device.*`（VID/PID/bcdDevice 探针）、`pcapng.*`（写器）、`packet.*`
  （帧解析，gen2 结构化移植自 gen1 capture.c）。
- gen2：`stream.*`（UHSIF 块解析）、`cmd.*`（命令/ACK）、`transport*`（libusb/replay）。
- gen1：`gen1/usb.*`（libusb 后端+维护通道）、`gen1/capture.*`（捕获引擎）、
  `gen1/fx2lp.*`、`gen1/fpga.*`（固件/码流编程，与上游保持一致）。