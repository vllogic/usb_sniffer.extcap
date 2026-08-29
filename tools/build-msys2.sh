#!/usr/bin/env bash
# USB Sniffer 2 extcap - Windows (MSYS2/MinGW) one-shot build script.
#
#  1) Install MSYS2 from https://www.msys2.org
#  2) Open "MSYS2 MINGW64" terminal (NOT "MSYS2 MSYS"): the x86_64-w64-mingw32
#     toolchain only appears on the MINGW64 environment after the steps below.
#  3) Run this script from the repo root:  bash extcap.usb_sniffer2/tools/build-msys2.sh
#
# Output: capture_usb_vllogic.exe  (install into %APPDATA%\Wireshark\extcap\)
set -euo pipefail

PACMAN_PKGS=(
  mingw-w64-x86_64-gcc
  mingw-w64-x86_64-make
  mingw-w64-x86_64-pkgconf
  mingw-w64-x86_64-libusb
)

echo "== installing toolchain + libusb (first run only) =="
pacman -S --needed --noconfirm "${PACMAN_PKGS[@]}"

cd "$(dirname "$0")/.."

echo "== building =="
mingw32-make clean
mingw32-make

echo "== done: $(pwd)/capture_usb_vllogic.exe =="
echo "install: mkdir -p \"\$APPDATA\\\\Wireshark\\\\extcap\" && cp capture_usb_vllogic.exe \"\$APPDATA\\\\Wireshark\\\\extcap\\\\\""
echo "then restart Wireshark: the 'Vllogic: USB Sniffer 2' interface appears in the capture list."