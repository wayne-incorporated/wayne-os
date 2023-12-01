// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Download file to HPS.
 */

#include <iostream>
#include <memory>
#include <string>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/strings/string_number_conversions.h>

#include "hps/hps.h"
#include "hps/hps_reg.h"
#include "hps/util/command.h"

namespace {

int Download(std::unique_ptr<hps::HPS> hps,
             const base::CommandLine::StringVector& args) {
  if (args.size() != 3) {
    std::cerr << "Arg error: ... " << args[0] << " bank-id file" << std::endl;
    return 1;
  }
  int bank = 0;
  if (!base::StringToInt(args[1], &bank)) {
    std::cerr << "Illegal bank: " << args[1] << std::endl;
    return 1;
  }
  // Assume downloading to start of bank.
  if (hps->Download(hps::HpsBank(bank), base::FilePath(args[2]))) {
    std::cout << "Successful download" << std::endl;
    return 0;
  } else {
    std::cerr << "Download failed" << std::endl;
    return 1;
  }
}

Command dl("dl", "dl <bank-id> <file> - Download file to hps.", Download);

}  // namespace
