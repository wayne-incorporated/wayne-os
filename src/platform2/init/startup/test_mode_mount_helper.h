// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_TEST_MODE_MOUNT_HELPER_H_
#define INIT_STARTUP_TEST_MODE_MOUNT_HELPER_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>

#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"

namespace startup {

// This class defines the MountHelper behavior we will use when the device
// is running a test image.
class TestModeMountHelper : public startup::MountHelper {
 public:
  explicit TestModeMountHelper(std::unique_ptr<Platform> platform,
                               const startup::Flags& flags,
                               const base::FilePath& root,
                               const base::FilePath& stateful,
                               const bool dev_mode);

  // Bind mount the /var and /home/chronos mounts. The implementation
  // is different for test images and when in factory mode. It also
  // changes depending on the encrypted stateful USE flag.
  bool DoMountVarAndHomeChronos() override;

  // Returns a string representation of the MountHelper derived class
  // used, for test purposes.
  startup::MountHelperType GetMountHelperType() const override;
};

}  // namespace startup

#endif  // INIT_STARTUP_TEST_MODE_MOUNT_HELPER_H_
