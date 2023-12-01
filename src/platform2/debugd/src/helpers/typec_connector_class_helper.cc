// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/typec_connector_class_helper_utils.h"

using debugd::typec_connector_class_helper::kPortRegex;
using debugd::typec_connector_class_helper::kTypecSysfs;
using debugd::typec_connector_class_helper::ParseDirsAndExecute;
using debugd::typec_connector_class_helper::PrintPortInfo;

int main(int argc, char** argv) {
  if (argc != 1) {
    std::cout
        << "typec_connector_class_helper.cc does not accept any arguements."
        << std::endl;
    return 1;
  }

  if (!base::PathExists(base::FilePath(kTypecSysfs)))
    return 1;

  ParseDirsAndExecute(base::FilePath(kTypecSysfs), 0, kPortRegex,
                      &PrintPortInfo);
  return EXIT_SUCCESS;
}
