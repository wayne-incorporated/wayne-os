// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/switches/modemfwd_switches.h>

int main(int argc, char** argv) {
  DEFINE_bool(prepare_to_flash, false, "Put the modem in flash mode");
  DEFINE_string(flash_fw, "", "Flash file(s) containing firmware to the modem");
  DEFINE_bool(get_fw_info, false, "Get custpack information");
  DEFINE_string(shill_fw_revision, "", "Current fw version reported by Shill");
  DEFINE_bool(reboot, false, "Reboot the modem");
  DEFINE_bool(flash_mode_check, false, "Check if the modem is in flash mode");
  DEFINE_string(power_enable_gpio, "", "Modem power enable GPIO number");
  DEFINE_string(fw_version, "", "Version number of the firmware to flash");
  DEFINE_string(clear_attach_apn, "",
                "Clear attach APN according to carrier uuid");

  brillo::FlagHelper::Init(argc, argv, " herobrine helper for modemfwd");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  int num_opts = FLAGS_prepare_to_flash + !FLAGS_flash_fw.empty() +
                 FLAGS_get_fw_info + FLAGS_reboot + FLAGS_flash_mode_check +
                 !FLAGS_clear_attach_apn.empty();
  if (num_opts != 1) {
    LOG(ERROR) << "Must supply exactly one supported action";
    return EXIT_FAILURE;
  }

  if (FLAGS_prepare_to_flash) {
    return EXIT_SUCCESS;
  }

  if (FLAGS_get_fw_info) {
    const char kUnknownRevision[] = "unknown-revision";
    std::vector<std::string> res = base::SplitString(
        FLAGS_shill_fw_revision, " ", base::WhitespaceHandling::TRIM_WHITESPACE,
        base::SplitResult::SPLIT_WANT_NONEMPTY);
    if (res.empty()) {
      printf("%s:%s\n", modemfwd::kFwMain, kUnknownRevision);
      return EXIT_SUCCESS;
    }
    printf("%s:%s\n", modemfwd::kFwMain, res[0].c_str());
    return EXIT_SUCCESS;
  }

  if (FLAGS_flash_mode_check) {
    return EXIT_SUCCESS;
  }

  if (!FLAGS_clear_attach_apn.empty()) {
    return EXIT_SUCCESS;
  }

  if (FLAGS_reboot)
    return EXIT_SUCCESS;

  if (FLAGS_flash_fw.empty())
    return EXIT_SUCCESS;

  return EXIT_SUCCESS;
}
