// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// ICMP helper - emits info about ICMP connectivity to a specified host as json.
// Example output:
// { "4.2.2.1":
//     { "sent": 4,
//       "recvd": 4,
//       "time": 3005,
//       "min": 5.789000,
//       "avg": 5.913000,
//       "max": 6.227000,
//       "dev": 0.197000
//     }
// }
// All times are in milliseconds. "time" is the total time taken by ping(1).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <base/command_line.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

using base::StringPrintf;
using std::string;

namespace {

static const char kHelpMessage[] =
    "Usage: icmp [<switches>] <ip>\n\n"
    "Available switches:\n"
    "  --count=<number of packets> (default: 4)\n"
    "  --size=<packet size>\n"
    "  --ttl=<IP Time to Live>\n"
    "  --timeout=<time to wait for response>";

static const char kIPv4v6Chars[] = "ABCDEFabcdef0123456789.:";

static void Die(const string& why) {
  printf("<%s>\n", why.c_str());
  exit(1);
}

static int GetIntSwitch(const base::CommandLine* cl,
                        const string& name,
                        int default_value) {
  int val = default_value;
  if (cl->HasSwitch(name)) {
    string switch_value = cl->GetSwitchValueASCII(name);
    if (!base::StringToInt(switch_value, &val) || val <= 0) {
      Die(StringPrintf("Invalid %s switch: %s", name.c_str(),
                       switch_value.c_str()));
    }
  }
  return val;
}

}  // namespace

int main(int argc, char* argv[]) {
  char outbuf[1024];
  char ipbuf[128] = {0};
  FILE* out;
  int sent = -1, recvd = -1, loss = -1, errors = -1, time = -1;
  float min = 0.0, avg = 0.0, max = 0.0, mdev = 0.0;

  // Parse commandline switches.
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int count = GetIntSwitch(cl, "count", 4);
  int size = GetIntSwitch(cl, "size", 0);
  int ttl = GetIntSwitch(cl, "ttl", 0);
  int timeout = GetIntSwitch(cl, "timeout", 0);

  // Parse out the IP address.
  base::CommandLine::StringVector args = cl->GetArgs();
  if (args.size() != 1)
    Die(kHelpMessage);
  string ip_addr = args[0];
  if (!base::ContainsOnlyChars(ip_addr, kIPv4v6Chars))
    Die("not ip address");

  // Construct command.
  string size_out = size ? StringPrintf("-s %d", size) : "";
  string ttl_out = ttl ? StringPrintf("-t %d", ttl) : "";
  string timeout_out = timeout ? StringPrintf("-W %d", timeout) : "";
  string command = StringPrintf("/bin/ping -c %d -w 10 -n %s %s %s %s", count,
                                ttl_out.c_str(), size_out.c_str(),
                                timeout_out.c_str(), ip_addr.c_str());

  // Execute!
  out = popen(command.c_str(), "r");
  if (!out)
    Die("can't create subprocess");

  // Parse output.
  while (fgets(outbuf, sizeof(outbuf), out)) {
    if (sscanf(outbuf, "From %127s icmp_seq=", ipbuf) == 1) {
      // If there is a colon after the ip, strip it.
      char* last_char = ipbuf + strlen(ipbuf) - 1;
      if (*last_char == ':')
        *last_char = '\0';
      continue;

    } else if (sscanf(outbuf,
                      "%d packets transmitted, %d received, %d%% packet loss,"
                      " time %dms",
                      &sent, &recvd, &loss, &time) == 4) {
      continue;

    } else if (sscanf(outbuf,
                      "%d packets transmitted, %d received, +%d errors,"
                      " %d%% packet loss, time %dms",
                      &sent, &recvd, &errors, &loss, &time) == 5) {
      continue;

    } else if (sscanf(outbuf, "rtt min/avg/max/mdev = %f/%f/%f/%f ms", &min,
                      &avg, &max, &mdev) == 4) {
      continue;
    }
  }
  pclose(out);
  if (time == -1)
    Die("didn't get all output");
  string ip_out = ipbuf[0] ? ipbuf : ip_addr;

  printf("{ \"%s\":\n", ip_out.c_str());
  printf("    { \"sent\": %d,\n", sent);
  printf("      \"recvd\": %d,\n", recvd);
  printf("      \"time\": %d,\n", time);
  printf("      \"min\": %f,\n", min);
  printf("      \"avg\": %f,\n", avg);
  printf("      \"max\": %f,\n", max);
  printf("      \"dev\": %f\n", mdev);
  printf("    }\n");
  printf("}\n");
  return 0;
}
