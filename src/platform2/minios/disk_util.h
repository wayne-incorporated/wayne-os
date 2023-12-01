// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_DISK_UTIL_H_
#define MINIOS_DISK_UTIL_H_

#include <string>

#include <base/files/file_path.h>

namespace minios {

class DiskUtil {
 public:
  DiskUtil();
  virtual ~DiskUtil() = default;

  DiskUtil(const DiskUtil&) = delete;
  DiskUtil& operator=(const DiskUtil&) = delete;

  // Calls the `get_fixed_dst_drive()` bash function.
  // Returns empty `base::FilePath` on error or if not found.
  virtual base::FilePath GetFixedDrive();

  // Return the path to the stateful partition.
  // Otherwise, returns an empty `base::FilePath`.
  virtual base::FilePath GetStatefulPartition(const base::FilePath& drive);

  // Only for testing.
  // Changes the paths for testing purposes.
  void SetDevicePathForTest(const base::FilePath& device_path);
  void SetStoragePathForTest(const base::FilePath& storage_path);

 private:
  base::FilePath device_path_;
  base::FilePath storage_path_;
};

}  // namespace minios

#endif  // MINIOS_DISK_UTIL_H__
