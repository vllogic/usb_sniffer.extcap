# USB Sniffer (gen1) / USB Sniffer 2 (gen2) - Wireshark extcap plugin.
#
#   make            build the extcap binary
#   make install    install into the Wireshark extcap directory
#   make udev       install udev rules (Linux only)
#   make test       run the regression suite (offline, needs python3)
#   make clean
#
# Supported platforms:
#   - Linux   (gcc/clang, libusb-1.0 via pkg-config)
#   - macOS   (Homebrew libusb-1.0; pkg-config located automatically)
#   - Windows (MSYS2/MINGW, libusb-1.0 static via pkg-config)
#
# Override PKG_CONFIG=<path> if pkg-config is not on PATH / not detected.

CFLAGS += -W -Wall --std=gnu11 -O2 -g
CFLAGS += -Isrc -Isrc/gen1

SRCS = \
  src/os_common.c \
  src/pcapng.c \
  src/stream.c \
  src/cmd.c \
  src/packet.c \
  src/extcap.c \
  src/transport.c \
  src/transport_libusb.c \
  src/transport_replay.c \
  src/device.c \
  src/gen1/usb.c \
  src/gen1/fx2lp.c \
  src/gen1/fpga.c \
  src/gen1/capture.c \
  src/main.c

HDRS = \
  src/os_common.h \
  src/pcapng.h \
  src/uhsif.h \
  src/stream.h \
  src/cmd.h \
  src/packet.h \
  src/transport.h \
  src/transport_internal.h \
  src/extcap.h \
  src/capture_defs.h \
  src/device.h \
  src/gen1/usb.h \
  src/gen1/capture.h \
  src/gen1/fx2lp.h \
  src/gen1/fpga.h

# Override UNAME too if cross-building (e.g. UNAME=Darwin make -n).
UNAME ?= $(shell uname)

ifeq ($(UNAME), Linux)
  BIN = capture_usb_vllogic
  PKG_CONFIG ?= pkg-config
  CFLAGS += -D_GNU_SOURCE
  CFLAGS += `$(PKG_CONFIG) --cflags libusb-1.0`
  LDFLAGS += -lm
  LDFLAGS += `$(PKG_CONFIG) --libs libusb-1.0`
  EXTCAP_PATH = $(HOME)/.local/lib/wireshark/extcap
  UDEV_RULE = 90-usb-sniffer.rules
else ifeq ($(UNAME), Darwin)
  BIN = capture_usb_vllogic
  # Homebrew pkg-config: Apple Silicon /opt/homebrew, Intel /usr/local.
  BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
  ifeq ($(BREW_PREFIX),)
    BREW_PREFIX := /usr/local
  endif
  PKG_CONFIG ?= $(BREW_PREFIX)/bin/pkg-config
  CFLAGS += `$(PKG_CONFIG) --cflags libusb-1.0`
  LDFLAGS += -lm
  LDFLAGS += `$(PKG_CONFIG) --libs libusb-1.0`
  EXTCAP_PATH = $(HOME)/.local/lib/wireshark/extcap
  UDEV_RULE =
else ifneq ($(findstring MINGW,$(UNAME)),)
  BIN = capture_usb_vllogic.exe
  PKG_CONFIG ?= pkg-config
  CFLAGS += -D_GNU_SOURCE
  CFLAGS += `$(PKG_CONFIG) --cflags libusb-1.0`
  LDFLAGS += -Wl,--subsystem,console
  LIB_PATH = `$(PKG_CONFIG) --variable=libdir libusb-1.0`
  LDFLAGS += $(LIB_PATH)/libusb-1.0.a
  LDFLAGS += $(LIB_PATH)/libwinpthread.a
  LDFLAGS += -lws2_32
  EXTCAP_PATH = $(APPDATA)/Wireshark/extcap/
  UDEV_RULE =
else
  $(error Unsupported platform: $(UNAME))
endif

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	gcc $(CFLAGS) $(SRCS) -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)
	rm -rf test

# --- Offline regression suite ----------------------------------------------
# The reference samples live in the upstream usb-sniffer checkout; override
# SAMPLE_DIR if the repo is checked out elsewhere.

SAMPLE_DIR ?= /home/llp/ataradov.usb-sniffer/doc
TEST_DIR   = test
PY         = python3

.PHONY: test test-ls test-fs test-hs test-features

$(TEST_DIR)/.mkdir:
	mkdir -p $(TEST_DIR)
	touch $@

test: test-ls test-fs test-hs test-features
	@echo "All tests passed"

test-features: $(BIN) $(TEST_DIR)/.mkdir
	$(PY) tools/feature_tests.py ./$(BIN) $(TEST_DIR)

test-ls test-fs test-hs: | sample-check

.PHONY: sample-check
sample-check:
	@if [ ! -d "$(SAMPLE_DIR)" ]; then \
		echo "reference samples not found at: $(SAMPLE_DIR)"; \
		echo "set SAMPLE_DIR=/path/to/ref.ataradov.usb-sniffer/doc"; \
		exit 1; \
	fi

test-ls: $(BIN) $(TEST_DIR)/.mkdir
	$(PY) tools/make_fake_stream.py --speed ls --in $(SAMPLE_DIR)/usb_ls_mouse.pcapng --out $(TEST_DIR)/usb_ls_mouse.bin
	./$(BIN) --replay $(TEST_DIR)/usb_ls_mouse.bin --fifo $(TEST_DIR)/usb_ls_mouse.pcapng --speed ls --fold
	$(PY) tools/check_pcapng.py $(TEST_DIR)/usb_ls_mouse.pcapng $(SAMPLE_DIR)/usb_ls_mouse.pcapng

test-fs: $(BIN) $(TEST_DIR)/.mkdir
	$(PY) tools/make_fake_stream.py --speed fs --in $(SAMPLE_DIR)/usb_fs_vcp.pcapng --out $(TEST_DIR)/usb_fs_vcp.bin
	./$(BIN) --replay $(TEST_DIR)/usb_fs_vcp.bin --fifo $(TEST_DIR)/usb_fs_vcp.pcapng --speed fs --fold
	$(PY) tools/check_pcapng.py $(TEST_DIR)/usb_fs_vcp.pcapng $(SAMPLE_DIR)/usb_fs_vcp.pcapng

test-hs: $(BIN) $(TEST_DIR)/.mkdir
	$(PY) tools/make_fake_stream.py --speed hs --in $(SAMPLE_DIR)/usb_hs_flash_drive.pcapng --out $(TEST_DIR)/usb_hs_flash_drive.bin
	./$(BIN) --replay $(TEST_DIR)/usb_hs_flash_drive.bin --fifo $(TEST_DIR)/usb_hs_flash_drive.pcapng --speed hs --fold
	$(PY) tools/check_pcapng.py $(TEST_DIR)/usb_hs_flash_drive.pcapng $(SAMPLE_DIR)/usb_hs_flash_drive.pcapng

install: $(BIN)
	install -d $(EXTCAP_PATH)
	install -m 755 $< $(EXTCAP_PATH)/

udev: $(UDEV_RULE)
	@if [ -n "$(UDEV_RULE)" ]; then \
		echo "Installing $(UDEV_RULE) into /etc/udev/rules.d/"; \
		install -m 644 $(UDEV_RULE) /etc/udev/rules.d/; \
	else \
		echo "udev rules are only applicable on Linux"; \
	fi

.PHONY: all clean test test-ls test-fs test-hs test-features install udev