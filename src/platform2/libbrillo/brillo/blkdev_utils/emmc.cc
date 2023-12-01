// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/emmc.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/brillo_export.h>
#include <brillo/process/process.h>

namespace brillo {

namespace {

constexpr const char kMmcTool[] = "mmc";

}  // namespace

bool Emmc::SupportPhysicalErasure() const {
  return true;
}

LogicalErasureIoctl Emmc::GetLogicalErasureIoctlType() const {
  return LogicalErasureIoctl::blksecdiscard;
}

bool Emmc::PhysicalErasure(const base::FilePath& device_path,
                           const uint64_t device_length) const {
  brillo::ProcessImpl mmc;
  mmc.SetSearchPath(true);
  mmc.AddArg(kMmcTool);
  mmc.AddStringOption("sanitize", device_path.value().c_str());
  mmc.RedirectUsingMemory(STDOUT_FILENO);
  mmc.RedirectUsingMemory(STDERR_FILENO);

  LOG(INFO) << "Running `mmc sanitize` ...";
  int mmc_ret = mmc.Run();
  if (mmc_ret) {
    LOG(ERROR) << "Failed to run `mmc sanitize` (Error Code: " << mmc_ret
               << "):\n"
               << mmc.GetOutputString(STDERR_FILENO);
  } else {
    LOG(INFO) << mmc.GetOutputString(STDOUT_FILENO);
  }

  return mmc_ret == 0;
}

}  // namespace brillo
