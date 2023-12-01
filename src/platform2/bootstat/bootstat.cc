// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implementation of the 'bootstat' command, part of the Chromium OS
// 'bootstat' facility.  The command provides a command line wrapper
// around the key functionality declared in "bootstat.h"

#include <libgen.h>
#include <stdio.h>

#include <string>

#include "base/command_line.h"

#include "bootstat/bootstat.h"

namespace {

void usage(char* cmd) {
  fprintf(stderr, "usage: %s [--sync=rtc] <event-name>\n", basename(cmd));
  exit(EXIT_FAILURE);
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  base::CommandLine::StringVector args = cl->GetArgs();

  // Event name must always be provided (and only that).
  if (args.size() != 1)
    usage(argv[0]);

  if (cl->HasSwitch("sync")) {
    std::string sync = cl->GetSwitchValueASCII("sync");
    if (sync == "rtc")
      bootstat::BootStat().LogRtcSync(args[0].c_str());
    else
      usage(argv[0]);
  } else {
    bootstat::BootStat().LogEvent(args[0].c_str());
  }
  return EXIT_SUCCESS;
}
