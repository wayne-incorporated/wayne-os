// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/lockfile_checker.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "power_manager/common/util.h"

namespace power_manager::system {

namespace {

// Default directory used to check if a PID exists.
const char kDefaultProcDir[] = "/proc";

// Returns true if |lockfile| exists and contains the PID of an existing process
// (with a directory in |proc_dir|).
bool IsValid(const base::FilePath& lockfile, const base::FilePath& proc_dir) {
  if (!base::PathExists(lockfile))
    return false;

  int64_t pid = -1;
  if (!util::ReadInt64File(lockfile, &pid))
    return false;

  if (!base::DirectoryExists(proc_dir.Append(base::NumberToString(pid)))) {
    LOG(WARNING) << lockfile.value() << " contains stale/invalid PID \"" << pid
                 << "\"";
    return false;
  }
  return true;
}

}  // namespace

LockfileChecker::LockfileChecker(const base::FilePath& dir,
                                 const std::vector<base::FilePath>& files)
    : proc_dir_(kDefaultProcDir), dir_(dir), files_(files) {}

LockfileChecker::~LockfileChecker() = default;

std::vector<base::FilePath> LockfileChecker::GetValidLockfiles() const {
  std::vector<base::FilePath> paths;

  base::FileEnumerator enumerator(dir_, false, base::FileEnumerator::FILES);
  for (auto path = enumerator.Next(); !path.empty(); path = enumerator.Next()) {
    if (IsValid(path, proc_dir_))
      paths.push_back(path);
  }

  for (const auto& path : files_) {
    if (IsValid(path, proc_dir_))
      paths.push_back(path);
  }

  return paths;
}

}  // namespace power_manager::system
