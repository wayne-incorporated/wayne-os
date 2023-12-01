// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/ufs.h"

#include <base/bits.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/brillo_export.h>
#include <brillo/process/process.h>

namespace brillo {

namespace {

constexpr char kDevToController[] = "../../../../../";
constexpr char kUnitDescriptorDir[] = "device/unit_descriptor";
constexpr uint32_t kUFSPurgeTimeoutSecPerGB = 5;
constexpr uint64_t kGiB = 1024 * 1024 * 1024;
constexpr const char kFactoryUfsTool[] = "factory_ufs";

}  // namespace

bool IsUfs(const base::FilePath& dev_node) {
  base::FilePath unit_descriptor_node = dev_node.Append(kUnitDescriptorDir);
  return base::DirectoryExists(unit_descriptor_node);
}

base::FilePath UfsSysfsToControllerNode(const base::FilePath& dev_node) {
  if (!base::PathExists(dev_node)) {
    PLOG(ERROR) << "Node doesn't exists: " << dev_node;
    return base::FilePath();
  }

  base::FilePath path = dev_node.Append(kDevToController);
  base::FilePath normalized_path;

  normalized_path = base::MakeAbsoluteFilePath(path);
  if (normalized_path.empty()) {
    LOG(ERROR) << "Couldn't normalize: " << path;
    return base::FilePath();
  }

  return normalized_path;
}

bool Ufs::SupportPhysicalErasure() const {
  return true;
}

LogicalErasureIoctl Ufs::GetLogicalErasureIoctlType() const {
  return LogicalErasureIoctl::blkdiscard;
}

bool Ufs::PhysicalErasure(const base::FilePath& device_path,
                          const uint64_t device_length) const {
  int purge_timeout_sec = base::bits::AlignUp(device_length, kGiB) / kGiB *
                          kUFSPurgeTimeoutSecPerGB;
  brillo::ProcessImpl factory_ufs;
  factory_ufs.SetSearchPath(true);
  factory_ufs.AddArg(kFactoryUfsTool);
  factory_ufs.AddArg("purge");
  factory_ufs.AddIntOption("-t", purge_timeout_sec);
  factory_ufs.RedirectUsingMemory(STDOUT_FILENO);
  factory_ufs.RedirectUsingMemory(STDERR_FILENO);

  LOG(INFO) << "Running `factory_ufs purge` with timeout set to "
            << purge_timeout_sec << " seconds ...";
  int factory_ufs_ret = factory_ufs.Run();
  if (factory_ufs_ret) {
    LOG(ERROR) << "Failed to run `factory_ufs purge` (Error Code: "
               << factory_ufs_ret << "):\n"
               << factory_ufs.GetOutputString(STDERR_FILENO);
  } else {
    LOG(INFO) << factory_ufs.GetOutputString(STDOUT_FILENO);
  }

  return factory_ufs_ret == 0;
}

}  // namespace brillo
