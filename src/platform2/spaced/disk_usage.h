// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SPACED_DISK_USAGE_H_
#define SPACED_DISK_USAGE_H_

#include <base/files/file_path.h>

namespace spaced {
// Abstract class that defines the interface for both disk usage util and its
// D-Bus proxy.
class DiskUsageUtil {
 public:
  virtual ~DiskUsageUtil() = default;

  virtual int64_t GetFreeDiskSpace(const base::FilePath& path) = 0;
  virtual int64_t GetTotalDiskSpace(const base::FilePath& path) = 0;
  virtual int64_t GetRootDeviceSize() = 0;
};

}  // namespace spaced

#endif  // SPACED_DISK_USAGE_H_
