// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/mount.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/values.h>

#include "init/startup/factory_mode_mount_helper.h"
#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"

namespace {

constexpr char kOptionsFile[] =
    "dev_image/factory/init/encstateful_mount_option";
constexpr char kVar[] = "var";
constexpr char kHomeChronos[] = "home/chronos";

}  // namespace

namespace startup {

// Constructor for FactoryModeMountHelper when the device is
// in factory mode.
FactoryModeMountHelper::FactoryModeMountHelper(
    std::unique_ptr<Platform> platform,
    const Flags& flags,
    const base::FilePath& root,
    const base::FilePath& stateful,
    const bool dev_mode)
    : MountHelper(std::move(platform), flags, root, stateful, dev_mode) {}

bool FactoryModeMountHelper::DoMountVarAndHomeChronos() {
  base::FilePath option_file = GetStateful().Append(kOptionsFile);
  std::string option = "";
  if (base::PathExists(option_file)) {
    base::ReadFileToString(option_file, &option);
  }
  if (option == "tmpfs") {
    // Mount tmpfs to /var/. When booting from USB disk, writing to /var/
    // slows down system performance dramatically. Since there is no need to
    // really write to stateful partition, using option 'tmpfs' will mount
    // tmpfs on /var to improve performance. (especially when running
    // tests like touchpad, touchscreen).
    base::FilePath var = GetRoot().Append(kVar);
    if (!platform_->Mount(base::FilePath("tmpfs_var"), var, "tmpfs", 0, "")) {
      return false;
    }
    base::FilePath stateful_home_chronos = GetStateful().Append(kHomeChronos);
    base::FilePath home_chronos = GetRoot().Append(kHomeChronos);
    if (!platform_->Mount(stateful_home_chronos, home_chronos, "", MS_BIND,
                          "")) {
      return false;
    }
    return true;
  }
  // Mount /var and /home/chronos in the unencrypted mode.
  return MountVarAndHomeChronosUnencrypted();
}

MountHelperType FactoryModeMountHelper::GetMountHelperType() const {
  return MountHelperType::kFactoryMode;
}

}  // namespace startup
