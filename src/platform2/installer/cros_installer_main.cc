// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/flag_helper.h>

#include "installer/chromeos_install_config.h"
#include "installer/chromeos_postinst.h"

int main(int argc, char* argv[]) {
  DEFINE_string(type, "", "Install type, one of: postinst.");

  // postinst flags.
  DEFINE_string(bios, "", "Bios type, one of: secure, legacy, efi, and uboot.");
  DEFINE_string(install_dev, "", "Install device. e.g. /");
  DEFINE_string(install_dir, "", "Install directory. e.g. /tmp/blah");
  DEFINE_string(defer_update_action, "",
                "Defers(holds)/applies final FW + OS updates, "
                "one of: '' (Default: empty), 'hold', and 'apply'.");
  DEFINE_bool(force_update_firmware, false,
              "Forces a fw update with OS update.");

  brillo::FlagHelper::Init(argc, argv, "cros_installer");

  if (FLAGS_type == "postinst") {
    // Unknown means we will attempt to autodetect later on.
    BiosType bios_type = BiosType::kUnknown;
    if (!FLAGS_bios.empty() && !StrToBiosType(FLAGS_bios, &bios_type)) {
      LOG(ERROR) << "Invalid bios type: " << FLAGS_bios;
      return 1;
    }
    if (FLAGS_install_dev.empty()) {
      LOG(ERROR) << "--install_dev is empty.";
      return 1;
    }
    if (FLAGS_install_dir.empty()) {
      LOG(ERROR) << "--install_dir is empty.";
      return 1;
    }
    DeferUpdateAction defer_update_action;
    if (!StrToDeferUpdateAction(FLAGS_defer_update_action,
                                &defer_update_action)) {
      LOG(ERROR) << "Invalid --defer_update_action: "
                 << FLAGS_defer_update_action;
      return 1;
    }

    int exit_code = 0;
    if (!RunPostInstall(base::FilePath(FLAGS_install_dev),
                        base::FilePath(FLAGS_install_dir), bios_type,
                        defer_update_action, FLAGS_force_update_firmware,
                        &exit_code)) {
      return exit_code ? exit_code : 1;
    }
  } else {
    LOG(ERROR) << "Invalid --type flag is passed.";
    return 1;
  }

  return 0;
}
