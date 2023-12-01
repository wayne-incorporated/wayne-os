// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Provides the implementation of StatefulRecovery.

#include "cryptohome/stateful_recovery/stateful_recovery.h"

#include <linux/reboot.h>
#include <sys/reboot.h>
#include <unistd.h>

#include <base/logging.h>
#include <base/values.h>

#include <brillo/dbus/dbus_connection.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "cryptohome/platform.h"

int main(int argc, char** argv) {
  DEFINE_bool(reboot, true, "Reboot at end of recovery");
  DEFINE_string(flag_file, cryptohome::StatefulRecovery::kFlagFile,
                "Location of the flag file created by recovery image");
  brillo::FlagHelper::Init(argc, argv, "Stateful and User recovery");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  if (getuid() != 0) {
    LOG(ERROR) << argv[0] << " must be run as root";
    return 1;
  }

  cryptohome::Platform platform;

  // Setup libbrillo dbus.
  brillo::DBusConnection connection;
  scoped_refptr<dbus::Bus> bus = connection.Connect();
  DCHECK(bus) << "Failed to connect to system bus through libbrillo";
  auto userdataauth_proxy =
      std::make_unique<org::chromium::UserDataAuthInterfaceProxy>(bus);
  auto policy_provider = std::make_unique<policy::PolicyProvider>();

  // Do Stateful Recovery if requested.
  cryptohome::StatefulRecovery recovery(&platform, userdataauth_proxy.get(),
                                        policy_provider.get(), FLAGS_flag_file);
  if (recovery.Requested()) {
    if (recovery.Recover()) {
      LOG(INFO) << "Stateful recovery was performed successfully.";
    } else {
      LOG(ERROR) << "Stateful recovery failed.";
    }
    if (FLAGS_reboot) {
      // On Chrome hardware, sets the recovery request field and reboots.
      if (system("/usr/bin/crossystem recovery_request=1") != 0) {
        LOG(ERROR) << "Failed to set recovery request!";
      }
      platform.Sync();
      reboot(LINUX_REBOOT_CMD_RESTART);
    }
  }
  return 0;
}
