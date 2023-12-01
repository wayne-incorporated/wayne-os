// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_PROCFS_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_PROCFS_UTILS_H_

#include <sys/types.h>

#include <base/files/file_path.h>

namespace diagnostics {

// Indices of fields of interest in /proc/[pid]/stat. These should be kept in
// numerical order. Note that this is not an enum class so that it can be
// implicitly converted to ints when used as an index into an array or vector.
enum ProcPidStatIndices {
  kProcessID = 0,
  kName = 1,
  kState = 2,
  kParentProcessID = 3,
  kProcessGroupID = 4,
  kPriority = 17,
  kNice = 18,
  kThreads = 19,
  kStartTime = 21,
  kMaxValue = kStartTime,  // Must be updated whenever a larger index is added.
};

// Files read from a process subdirectory of procfs.
extern const char kProcessCmdlineFile[];
extern const char kProcessStatFile[];
extern const char kProcessStatmFile[];
extern const char kProcessStatusFile[];
extern const char kProcessIOFile[];

// Returns an absolute path to the procfs subdirectory containing files related
// to the process with ID |pid|. On a real device, this will be /proc/|pid|.
base::FilePath GetProcProcessDirectoryPath(const base::FilePath& root_dir,
                                           pid_t pid);

// Returns an absolute path to the cpuinfo file in procfs. On a real device,
// this will be /proc/cpuinfo.
base::FilePath GetProcCpuInfoPath(const base::FilePath& root_dir);

// Returns an absolute path to the stat file in procfs. On a real device, this
// will be /proc/stat.
base::FilePath GetProcStatPath(const base::FilePath& root_dir);

// Returns an absolute path to the uptime file in procfs. On a real device, this
// will be /proc/uptime.
base::FilePath GetProcUptimePath(const base::FilePath& root_dir);

// Returns an absolute path to the crypto file in procfs. On a real device,
// this will be /proc/crypto.
base::FilePath GetProcCryptoPath(const base::FilePath& root_dir);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_PROCFS_UTILS_H_
