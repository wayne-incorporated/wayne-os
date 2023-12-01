// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Command handler.
 */

#include <iomanip>
#include <iostream>
#include <memory>
#include <utility>

#include <string.h>

#include <base/command_line.h>
#include <base/strings/stringprintf.h>

#include "hps/dev.h"
#include "hps/hps.h"
#include "hps/hps_reg.h"
#include "hps/util/command.h"
#include "hps/utils.h"

namespace {

int SendCmd(std::unique_ptr<hps::HPS> hps,
            const base::CommandLine::StringVector& args) {
  int cmd;

  if (args.size() <= 1) {
    std::cerr << "Missing command ('reset', 'launch' or 'appl' expected)"
              << std::endl;
    return 1;
  }
  if (args[1] == "reset") {
    cmd = hps::R3::kReset;
  } else if (args[1] == "launch") {
    cmd = hps::R3::kLaunch1;
  } else if (args[1] == "appl") {
    cmd = hps::R3::kLaunchAppl;
  } else {
    std::cerr << args[0] << ": Unknown command (" << args[1] << ")"
              << std::endl;
    return 1;
  }

  std::cout << "Sending cmd value 0x" << std::hex << std::setfill('0')
            << std::setw(4) << cmd << " to register 3" << std::endl;
  if (hps->Device()->WriteReg(hps::HpsReg::kSysCmd, cmd)) {
    std::cout << "Success!" << std::endl;
  } else {
    std::cout << "Write failed!" << std::endl;
  }
  return 0;
}

Command cmd("cmd",
            "cmd [ reset | launch | appl ] - Send command to hps.",
            SendCmd);

}  // namespace
