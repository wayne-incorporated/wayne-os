// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Enable/disable feature(s).
 */

#include <iomanip>
#include <iostream>
#include <memory>

#include <base/command_line.h>
#include <base/strings/string_number_conversions.h>

#include "hps/hps.h"
#include "hps/hps_reg.h"
#include "hps/util/command.h"

namespace {

// Argument is feature id
// 0 - feature 1
// 1 - feature 2
int FeatureControl(std::unique_ptr<hps::HPS> hps,
                   const base::CommandLine::StringVector& args) {
  int feat = 0;
  if (args.size() != 2) {
    std::cerr << "Feature id required (0, 1)" << std::endl;
    return 1;
  }
  if (!base::StringToInt(args[1], &feat) || feat < 0 || feat > 1) {
    std::cerr << args[1] << ": illegal feature id. "
              << "Valid values are 0, 1." << std::endl;
    return 1;
  }
  bool result;
  if (args[0] == "enable") {
    result = hps->Enable(feat);
  } else {
    result = hps->Disable(feat);
  }
  if (result) {
    std::cout << "Success!" << std::endl;
    return 0;
  } else {
    std::cout << "Feature control failed!" << std::endl;
    return 1;
  }
}

Command enableCmd("enable",
                  "enable feature-id - "
                  "Enable feature, valid id values are 0, 1",
                  FeatureControl);
Command disableCmd("disable",
                   "disable feature-id - "
                   "Disable feature, valid id values are 0, 1",
                   FeatureControl);

}  // namespace
