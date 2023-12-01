// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/procfs_utils.h"

#include <string>

#include <base/strings/string_number_conversions.h>

namespace diagnostics {

const char kProcessCmdlineFile[] = "cmdline";
const char kProcessStatFile[] = "stat";
const char kProcessStatmFile[] = "statm";
const char kProcessStatusFile[] = "status";
const char kProcessIOFile[] = "io";

base::FilePath GetProcProcessDirectoryPath(const base::FilePath& root_dir,
                                           pid_t pid) {
  return root_dir.Append("proc").Append(base::NumberToString(pid));
}

base::FilePath GetProcCpuInfoPath(const base::FilePath& root_dir) {
  return root_dir.Append("proc/cpuinfo");
}

base::FilePath GetProcStatPath(const base::FilePath& root_dir) {
  return root_dir.Append("proc/stat");
}

base::FilePath GetProcUptimePath(const base::FilePath& root_dir) {
  return root_dir.Append("proc/uptime");
}

base::FilePath GetProcCryptoPath(const base::FilePath& root_dir) {
  return root_dir.Append("proc/crypto");
}

}  // namespace diagnostics
