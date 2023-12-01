// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_LOGGER_H_
#define MINIOS_LOGGER_H_

#include <memory>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/scoped_generic.h>
#include <brillo/namespaces/platform.h>

#include "minios/disk_util.h"

namespace minios {

extern const char kLogPath[];
extern const char kMiniOSLogsDirectory[];

class Logger {
 public:
  Logger(std::unique_ptr<DiskUtil> disk_util,
         std::unique_ptr<brillo::Platform> platform,
         const base::FilePath& root_path = base::FilePath(kLogPath));
  virtual ~Logger() = default;

  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  // Should only be used by `ScopedUnmounter`.
  void Unmount();

  // Dumps the logs in the partition number 1 (the stateful partition), if
  // stateful partition does not exists or is not mountable, it will return
  // false. On success, will return true.
  bool DumpLogsIntoStateful();

  // Return the path where the partitions to dump into get mounted on.
  base::FilePath GetMountPath();

  // Only for tests.
  void SetRootPathForTest(const base::FilePath& root_path) {
    root_path_ = root_path;
  }

 private:
  std::unique_ptr<DiskUtil> disk_util_;
  std::unique_ptr<brillo::Platform> platform_;

  // The path to copy files/directories from.
  base::FilePath root_path_;
  // The temporary path to mount whichever partition to dump into.
  base::ScopedTempDir tmp_mount_;
};

}  // namespace minios

#endif  // MINIOS_LOGGER_H__
