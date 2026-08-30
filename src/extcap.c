// SPDX-License-Identifier: BSD-3-Clause

#include "extcap.h"
#include "pcapng.h"
#include "capture_defs.h"

#include <errno.h>

Options g_opt;

// Forward declarations (parse_command_line uses these).
static int get_capture_speed(void);
static int get_capture_trigger(void);

/*- Option parsing -----------------------------------------------------------*/

typedef struct
{
  int   short_name;
  char *long_name;
  char *arg_name;
  void *value;
  char *description;
} OsOption;

static const OsOption *find_long_option(const OsOption *options, char *text)
{
  for (const OsOption *opt = options; opt->value || opt->short_name; opt++)
  {
    if (opt->long_name && (0 == strcmp(opt->long_name, text)))
      return opt;
  }

  return NULL;
}

static const OsOption *find_short_option(const OsOption *options, char chr)
{
  for (const OsOption *opt = options; opt->value || opt->short_name; opt++)
  {
    if (opt->short_name == chr)
      return opt;
  }

  return NULL;
}

static int os_opt_parse(const OsOption *options, int argc, char *argv[])
{
  const OsOption *arg_opt = NULL;
  bool short_opt = false;

  for (int i = 1; i < argc; i++)
  {
    char *arg = argv[i];

    if (arg_opt)
    {
      if (arg[0] == '-')
        break;

      *(char **)arg_opt->value = arg;
      arg_opt = NULL;
      continue;
    }

    if (arg[0] != '-')
      return i;

    if (arg[1] == '-')
    {
      char *value = strchr(arg, '=');

      if (value)
        *value = 0;

      const OsOption *opt = find_long_option(options, &arg[2]);
      os_check(opt, "unrecognized option: %s", arg);

      // An inline "=value" is only meaningful for options that take an
      // argument.  Boolean options must never be written through a char**
      // cast: g_opt.extcap_version is a bool, and Wireshark >= 4.6 invokes
      // "--extcap-interfaces --extcap-version=<major.minor>", so the pointer
      // store would scribble over the adjacent bool fields of Options and
      // randomly drop the interface listing.  Tolerate and ignore the value.
      if (value)
      {
        if (opt->arg_name)
          *(char **)opt->value = &value[1];
        else
          *(bool *)opt->value = true;
      }
      else if (opt->arg_name)
        arg_opt = opt;
      else
        *(bool *)opt->value = true;

      short_opt = false;
    }
    else if (arg[1] == 0)
    {
      os_error("expected option name");
    }
    else
    {
      char *ptr = &arg[1];

      while (*ptr)
      {
        if (arg_opt)
          os_error("option -%c requires an argument", arg_opt->short_name);

        const OsOption *opt = find_short_option(options, *ptr);
        os_check(opt, "unrecognized option: -%c", *ptr);

        if (opt->arg_name)
          arg_opt = opt;
        else
          *(bool *)opt->value = true;

        ptr++;
      }

      short_opt = true;
    }
  }

  if (arg_opt)
  {
    if (short_opt)
      os_error("option -%c requires an argument", arg_opt->short_name);
    else
      os_error("option --%s requires an argument", arg_opt->long_name);
  }

  return argc;
}

static void print_help(const char *name, const OsOption *options)
{
  printf("USB Sniffer, built " __DATE__ " " __TIME__ "\n\n");
  printf("Usage: %s [options]\n", name);

  for (const OsOption *opt = options; opt->value || opt->short_name; opt++)
  {
    if (1 == opt->short_name)
    {
      puts("");
      puts(opt->long_name);
      continue;
    }

    printf("  ");
    if (opt->short_name)
      printf("-%c, ", opt->short_name);
    if (opt->long_name)
      printf("--%s", opt->long_name);
    if (opt->arg_name)
      printf(" <%s>", opt->arg_name);
    printf("\n          %s\n", opt->description);
  }

  printf("\n");

  exit(0);
}

void parse_command_line(int argc, char *argv[])
{
  static const OsOption options[] =
  {
    {  1, "General:", NULL, NULL, NULL },
    { 'h', "help",     NULL,      &g_opt.help,     "print this help message and exit" },

    {  1, "Capture:", NULL, NULL, NULL },
    { 's', "speed",    "speed",   &g_opt.speed,      "select USB speed: 'auto' (default), 'ls', 'fs' or 'hs'" },
    { 'l', "fold",     NULL,      &g_opt.fold_empty, "fold empty frames" },
    { 'e', "exclude",  NULL,      &g_opt.exclude_line_state, "exclude line state" },
    { 'n', "limit",    "number",  &g_opt.limit,      "limit the number of captured packets" },
    { 't', "trigger",  "type",    &g_opt.trigger,    "capture trigger: 'disabled' (default), 'low', 'high', 'falling' or 'rising'" },
    {  0 , "test",     NULL,      &g_opt.test,       "perform a transfer rate test (gen1)" },

    {  1, "Wireshark extcap:", NULL, NULL, NULL },
    {  0, "extcap-version",    NULL,      &g_opt.extcap_version,    "show the version of this utility" },
    {  0, "extcap-dlts",       NULL,      &g_opt.extcap_dlts,       "provide a list of dlts for the given interface" },
    {  0, "extcap-interfaces", NULL,      &g_opt.extcap_interfaces, "provide a list of interfaces to capture from" },
    {  0, "extcap-interface",  "name",    &g_opt.extcap_interface,  "provide the interface to capture from" },
    {  0, "extcap-config",     NULL,      &g_opt.extcap_config,     "provide a list of configurations for the given interface" },
    { 'c', "capture",          NULL,      &g_opt.extcap_capture,    "start capture" },
    { 'f', "fifo",             "name",    &g_opt.extcap_fifo,       "output fifo or file name" },

    {  1, "Development:", NULL, NULL, NULL },
    {  0, "replay",       "file", &g_opt.replay,     "replay a pre-recorded gen2 upstream stream for offline testing" },

    {  1, "Firmware update (gen1):", NULL, NULL, NULL },
    {  0 , "mcu-sram",   "name", &g_opt.mcu_sram,   "upload FX2LP firmware into the SRAM and run it" },
    {  0 , "mcu-eeprom", "name", &g_opt.mcu_eeprom, "program FX2LP firmware into the EEPROM" },
    {  0 , "fpga-sram",  "name", &g_opt.fpga_sram,  "upload BIT file into the FPGA SRAM" },
    {  0 , "fpga-flash", "name", &g_opt.fpga_flash, "program JED file into the FPGA flash" },
    {  0 , "fpga-erase", NULL,   &g_opt.fpga_erase, "erase FPGA flash" },
    {  0 },
  };

  int last = os_opt_parse(options, argc, argv);

  if (g_opt.help)
    print_help(argv[0], options);

  // Query-mode invocations (extcap protocol probes) may carry a trailing
  // tool-name argument (--extcap-version <toolname>); tolerate it instead
  // of rejecting the whole command line.
  if (last != argc && !(g_opt.extcap_version || g_opt.extcap_interfaces ||
                        g_opt.extcap_dlts || g_opt.extcap_config ||
                        g_opt.extcap_interface))
    os_check(argc > 1 && last == argc, "malformed command line, use '-h' for more information");

  g_opt.capture_speed = get_capture_speed();
  g_opt.capture_trigger = get_capture_trigger();
  g_opt.capture_limit = g_opt.limit ? strtoll(g_opt.limit, NULL, 10) : -1;
}

/*- Parsed value helpers -----------------------------------------------------*/

static int get_capture_speed(void)
{
  if (!g_opt.speed)
    return CaptureSpeed_Reset; // auto
  else if (0 == strcmp(g_opt.speed, "ls"))
    return CaptureSpeed_LS;
  else if (0 == strcmp(g_opt.speed, "fs"))
    return CaptureSpeed_FS;
  else if (0 == strcmp(g_opt.speed, "hs"))
    return CaptureSpeed_HS;
  else if (0 == strcmp(g_opt.speed, "auto"))
    return CaptureSpeed_Reset;

  os_error("unrecognized capture speed setting: '%s'", g_opt.speed);

  return 0;
}

static int get_capture_trigger(void)
{
  if (!g_opt.trigger)
    return CaptureTrigger_Disabled;
  else if (0 == strcmp(g_opt.trigger, "disabled"))
    return CaptureTrigger_Disabled;
  else if (0 == strcmp(g_opt.trigger, "low"))
    return CaptureTrigger_Low;
  else if (0 == strcmp(g_opt.trigger, "high"))
    return CaptureTrigger_High;
  else if (0 == strcmp(g_opt.trigger, "falling"))
    return CaptureTrigger_Falling;
  else if (0 == strcmp(g_opt.trigger, "rising"))
    return CaptureTrigger_Rising;

  os_error("unrecognized capture trigger setting: '%s'", g_opt.trigger);

  return 0;
}

/*- Extcap protocol ----------------------------------------------------------*/

bool handle_extcap_request(void)
{
  // Wireshark >= 4.6 enumerates tools with both flags in one invocation:
  //   --extcap-interfaces --extcap-version=<major.minor>
  // so the version reply is a preamble, not a standalone mode: emit it
  // whenever requested, then fall through to the interface listing.
  if (g_opt.extcap_version)
    printf("extcap {version=%s}{help=%s}{display=%s}\n", EXTCAP_VERSION, EXTCAP_URL, VENDOR_NAME);

  if (g_opt.extcap_interfaces)
  {
    printf("interface {value=" INTERFACE_NAME "}{display=%s}\n", VENDOR_NAME);
    return true;
  }

  if (g_opt.extcap_version)
    return true;

  if (g_opt.extcap_interface && strcmp(g_opt.extcap_interface, INTERFACE_NAME))
  {
    log_print("invalid interface, expected %s", INTERFACE_NAME);
    return true;
  }

  if (g_opt.extcap_dlts)
  {
    // The IDB actually written depends on the bus speed chosen at capture
    // time (dlt_for_speed(): 293/294/295, or 288 before speed detection),
    // so all four USB link types are advertised here.  Wireshark matches the
    // interface against the IDB found in the pcapng stream when the capture
    // starts.
    printf("dlt {number=%d}{name=USB_2_0}{display=USB 2.0}\n", LINKTYPE_USB_2_0);
    printf("dlt {number=%d}{name=USB_2_0_LOW_SPEED}{display=USB 2.0 Low Speed}\n", LINKTYPE_USB_2_0_LOW_SPEED);
    printf("dlt {number=%d}{name=USB_2_0_FULL_SPEED}{display=USB 2.0 Full Speed}\n", LINKTYPE_USB_2_0_FULL_SPEED);
    printf("dlt {number=%d}{name=USB_2_0_HIGH_SPEED}{display=USB 2.0 High Speed}\n", LINKTYPE_USB_2_0_HIGH_SPEED);
    return true;
  }

  if (g_opt.extcap_config)
  {
    // The two generations share the same capture options.
    printf("arg {number=0}{call=--speed}{display=Capture Speed}{tooltip=USB capture speed}{type=selector}\n");
    printf("value {arg=0}{value=auto}{display=Auto-Detect}{default=true}\n");
    printf("value {arg=0}{value=ls}{display=Low-Speed}{default=false}\n");
    printf("value {arg=0}{value=fs}{display=Full-Speed}{default=false}\n");
    printf("value {arg=0}{value=hs}{display=High-Speed}{default=false}\n");
    printf("arg {number=1}{call=--fold}{display=Fold empty frames}{tooltip=Fold frames that have no data or errors}{type=boolflag}\n");
    printf("arg {number=2}{call=--exclude}{display=Exclude Line State}{tooltip=Exclude Line State to reduce CPU usage}{type=boolflag}\n");
    printf("arg {number=3}{call=--trigger}{display=Capture Trigger}{tooltip=Condition used to start the capture}{type=selector}\n");
    printf("value {arg=3}{value=disabled}{display=Disabled}{default=true}\n");
    printf("value {arg=3}{value=low}{display=Low}{default=false}\n");
    printf("value {arg=3}{value=high}{display=High}{default=false}\n");
    printf("value {arg=3}{value=falling}{display=Falling}{default=false}\n");
    printf("value {arg=3}{value=rising}{display=Rising}{default=false}\n");
    printf("arg {number=4}{call=--limit}{display=Capture Limit}{tooltip=Limit the number of captured packets (0 for unlimited)}{type=integer}{range=0,10000000}{default=0}\n");
    return true;
  }

  return false;
}