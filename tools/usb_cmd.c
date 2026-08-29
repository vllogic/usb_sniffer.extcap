/* usb_cmd — send single/multiple UHSIF commands to the CH32H417 USB sniffer
 * via bulk EP1, and wait for the FPGA ACK block (unless --noack).
 *
 * Supported commands (CMD ids match fpga.h7p20/src/uhsif_usbsniffer.v):
 *
 *   reset  <0|1>        CMD_RESET          (0x01) capture engine reset level
 *   enable <0|1>        CMD_CAPTURE_ENABLE (0x02) capturing on/off
 *   speed  <ls|fs|hs|auto> CMD_CAPTURE_SPEED (0x03) 0/1/2/3 = LS/FS/HS/AUTO
 *   test   <0|1>        CMD_TEST_MODE      (0x04) counter-stream bandwidth test
 *   upload <len>        CMD_UPLOAD_PARAMS  (0x20) max payload dwords (1..4092)
 *   mask   <value>      CMD_CHANNEL_MASK   (0x21) channel mask (12 bits)
 *   raw    <id> <param> arbitrary command id/param
 *
 * Examples:
 *   usb_cmd enable 1
 *   usb_cmd speed fs enable 1
 *   usb_cmd --noack reset 1 reset 0
 *
 * Build: gcc -O2 -o usb_cmd usb_cmd.c -lusb-1.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>

#define VENDOR 0x1209
#define PRODUCT 0x6688
#define EP_OUT 0x01
#define EP_IN  0x81
#define BLK_MAGIC 0x6CC6

static unsigned g_seq = 0;
static int g_noack = 0;

static unsigned crc16(unsigned w1, unsigned w2, unsigned w3)
{
    /* CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB-first) over the 12
     * header bytes in wire order (w1, w2, w3, each little-endian), matching
     * uhsif.v crc16_hdr / uhsif.h uhsif_hdr_crc16. */
    unsigned crc = 0xFFFF;
    const unsigned words[3] = { w1, w2, w3 };

    for (int i = 0; i < 12; i++) {
        crc ^= ((words[i >> 2] >> ((i & 3) * 8)) & 0xFF) << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000u) ? ((crc << 1) ^ 0x1021u) : (crc << 1);
    }
    return crc & 0xFFFF;
}

static void put_le32(unsigned char *p, unsigned v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static void build_cmd(unsigned char *buf, unsigned cid, unsigned param)
{
    unsigned w1 = ((g_seq & 0xFF) << 8) | (cid & 0xFF);
    unsigned w2 = param;
    unsigned w3 = 0;
    unsigned w0 = (crc16(w1, w2, w3) << 16) | 0xC7F3u;
    put_le32(buf + 0,  w0);
    put_le32(buf + 4,  w1);
    put_le32(buf + 8,  w2);
    put_le32(buf + 12, w3);
}

static const char *cmd_name(unsigned cid)
{
    switch (cid) {
        case 0x01: return "RESET";
        case 0x02: return "ENABLE";
        case 0x03: return "SPEED";
        case 0x04: return "TEST";
        case 0x20: return "UPLOAD_PARAMS";
        case 0x21: return "CHANNEL_MASK";
        default:   return "RAW";
    }
}

int main(int argc, char **argv)
{
    /* parse options */
    int argp = 1;
    if (argc > 1 && !strcmp(argv[1], "--noack")) { g_noack = 1; argp = 2; }
    if (argc - argp < 2) {
        fprintf(stderr,
            "usage: %s [--noack] <cmd> <param> [<cmd> <param> ...]\n"
            "cmds: reset(0x01) enable(0x02) speed(0x03) test(0x04)\n"
            "      upload(0x20) mask(0x21) raw <id> <param>\n"
            "speed param: ls|fs|hs|auto or 0..3\n", argv[0]);
        return 1;
    }

    libusb_context *ctx = NULL;
    libusb_device_handle *dev = NULL;
    if (libusb_init(&ctx) < 0) return 1;
    dev = libusb_open_device_with_vid_pid(ctx, VENDOR, PRODUCT);
    if (!dev) { fprintf(stderr, "device %04x:%04x not found\n", VENDOR, PRODUCT); return 1; }
    libusb_set_configuration(dev, 1);
    if (libusb_kernel_driver_active(dev, 0) == 1)
        libusb_detach_kernel_driver(dev, 0);
    libusb_claim_interface(dev, 0);

    // drain residual IN data
    unsigned char drain[4096];
    for (int i = 0; i < 4; i++) {
        int r;
        int n = libusb_bulk_transfer(dev, EP_IN, drain, sizeof(drain), &r, 50);
        (void)n;
        if (i == 3 && r > 0)
            fprintf(stderr, "residual %d bytes dropped\n", r);
    }

    int rc = 0;
    while (argp < argc) {
        const char *name = argv[argp++];
        unsigned cid, param = 0;

        if (!strcmp(name, "raw") && argp < argc) {
            cid = (unsigned)strtoul(argv[argp++], NULL, 0);
            if (argp < argc) param = (unsigned)strtoul(argv[argp++], NULL, 0);
        } else if (!strcmp(name, "reset") && argp < argc) {
            cid = 0x01; param = (unsigned)strtoul(argv[argp++], NULL, 0) & 1;
        } else if (!strcmp(name, "enable") && argp < argc) {
            cid = 0x02; param = (unsigned)strtoul(argv[argp++], NULL, 0) & 1;
        } else if (!strcmp(name, "speed") && argp < argc) {
            cid = 0x03;
            const char *p = argv[argp++];
            if      (!strcmp(p, "ls"))   param = 0;
            else if (!strcmp(p, "fs"))   param = 1;
            else if (!strcmp(p, "hs"))   param = 2;
            else if (!strcmp(p, "auto")) param = 3;
            else param = (unsigned)strtoul(p, NULL, 0) & 3;
        } else if (!strcmp(name, "test") && argp < argc) {
            cid = 0x04; param = (unsigned)strtoul(argv[argp++], NULL, 0) & 1;
        } else if (!strcmp(name, "upload") && argp < argc) {
            cid = 0x20; param = (unsigned)strtoul(argv[argp++], NULL, 0) & 0xFFF;
        } else if (!strcmp(name, "mask") && argp < argc) {
            cid = 0x21; param = (unsigned)strtoul(argv[argp++], NULL, 0) & 0xFFF;
        } else {
            fprintf(stderr, "parse error at '%s'\n", name);
            rc = 2;
            break;
        }

        unsigned char buf[16];
        build_cmd(buf, cid, param);
        printf("-> [seq=%u] %-12s id=0x%02X param=0x%03X  "
               "%02X %02X %02X %02X | %02X %02X %02X %02X | %02X %02X %02X %02X | %02X %02X %02X %02X\n",
               g_seq, cmd_name(cid), cid, param,
               buf[0], buf[1], buf[2], buf[3],
               buf[4], buf[5], buf[6], buf[7],
               buf[8], buf[9], buf[10], buf[11],
               buf[12], buf[13], buf[14], buf[15]);

        int n;
        int r = libusb_bulk_transfer(dev, EP_OUT, buf, 16, &n, 500);
        if (r < 0) {
            printf("   EP1 OUT: %s\n", libusb_error_name(r));
            rc = 1;
        } else {
            printf("   EP1 OUT: ok (%d B)\n", n);
            if (!g_noack) {
                /* wait for the ACK (v2 block header, payload_len == 0) */
                unsigned char in[65536];
                int got = 0, ack_found = 0;
                unsigned timeout = 0;
                while (timeout < 2000 && !ack_found) {
                    r = libusb_bulk_transfer(dev, EP_IN, in + got, sizeof(in) - got, &n, 200);
                    if (r == 0 && n > 0) {
                        got += n;
                        /* scan for v2 headers: {crc16,6CC6,W1,W2,{seq,len,0}} */
                        for (int i = 0; i + 16 <= got; i++) {
                            unsigned w0 = (unsigned)in[i] | ((unsigned)in[i+1] << 8) |
                                          ((unsigned)in[i+2] << 16) | ((unsigned)in[i+3] << 24);
                            if ((w0 & 0xFFFF) == BLK_MAGIC) {
                                unsigned w1 = (unsigned)in[i+4] | ((unsigned)in[i+5] << 8) |
                                              ((unsigned)in[i+6] << 16) | ((unsigned)in[i+7] << 24);
                                unsigned w2 = (unsigned)in[i+8] | ((unsigned)in[i+9] << 8) |
                                              ((unsigned)in[i+10] << 16) | ((unsigned)in[i+11] << 24);
                                unsigned w3 = (unsigned)in[i+12] | ((unsigned)in[i+13] << 8) |
                                              ((unsigned)in[i+14] << 16) | ((unsigned)in[i+15] << 24);
                                unsigned exp_chk = crc16(w1, w2, w3);
                                printf("   ACK trailer: %d B (seq=%u len=%u crc16=%04X %s)\n",
                                       got - i, w3 >> 24, (w3 >> 12) & 0xFFF,
                                       (w0 >> 16) & 0xFFFF,
                                       (((w0 >> 16) & 0xFFFF) == exp_chk) ? "OK" : "CHK-MISMATCH");
                                ack_found = 1;
                                break;
                            }
                        }
                        timeout += 200;
                    } else {
                        timeout += 200;
                        if (timeout >= 2000)
                            printf("   ACK: timeout, %d stray bytes\n", got);
                    }
                }
                if (!ack_found && got)
                    printf("   ACK: none found, stray bytes %d\n", got);
            }
        }
        g_seq++;
    }

    libusb_release_interface(dev, 0);
    libusb_close(dev);
    libusb_exit(ctx);
    return rc;
}
