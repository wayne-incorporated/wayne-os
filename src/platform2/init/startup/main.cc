// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/values.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>

#include "init/crossystem.h"
#include "init/crossystem_impl.h"
#include "init/startup/chromeos_startup.h"
#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/mount_helper_factory.h"
#include "init/startup/platform_impl.h"

namespace {

constexpr char kLogFile[] = "/run/chromeos_startup.log";
constexpr char kLsbRelease[] = "/etc/lsb-release";
constexpr char kProcPath[] = "/proc";
constexpr char kStatefulPartition[] = "/mnt/stateful_partition";

}  // namespace

int main(int argc, char* argv[]) {
  // Set up logging to a file to record any unexpected but non-fatal
  // behavior.
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_FILE;
  settings.log_file_path = kLogFile;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  logging::InitLogging(settings);

  startup::Flags flags;
  startup::ChromeosStartup::ParseFlags(&flags);
  CrosSystemImpl* cros_system = new CrosSystemImpl();
  startup::MountHelperFactory mount_helper_factory(
      std::make_unique<startup::Platform>(), cros_system, flags,
      base::FilePath("/"), base::FilePath(kStatefulPartition),
      base::FilePath(kLsbRelease));
  auto mount_helper = mount_helper_factory.Generate();
  auto startup = std::make_unique<startup::ChromeosStartup>(
      std::unique_ptr<CrosSystemImpl>(cros_system), flags, base::FilePath("/"),
      base::FilePath(kStatefulPartition), base::FilePath(kLsbRelease),
      base::FilePath(kProcPath), std::make_unique<startup::Platform>(),
      std::move(mount_helper));

  return startup->Run();
}
