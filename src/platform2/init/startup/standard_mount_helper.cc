// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/values.h>

#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"
#include "init/startup/standard_mount_helper.h"

namespace startup {

// Constructor for StandardMountHelper when the device is
// not in dev mode.
StandardMountHelper::StandardMountHelper(std::unique_ptr<Platform> platform,
                                         const startup::Flags& flags,
                                         const base::FilePath& root,
                                         const base::FilePath& stateful,
                                         const bool dev_mode)
    : startup::MountHelper(
          std::move(platform), flags, root, stateful, dev_mode) {}

bool StandardMountHelper::DoMountVarAndHomeChronos() {
  return MountVarAndHomeChronos();
}

startup::MountHelperType StandardMountHelper::GetMountHelperType() const {
  return startup::MountHelperType::kStandardMode;
}

}  // namespace startup
