// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_LOCKFILE_CHECKER_H_
#define POWER_MANAGER_POWERD_SYSTEM_LOCKFILE_CHECKER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace power_manager::system {

// LockfileCheckerInterface checks lockfiles that are created to prevent powerd
// from taking various actions. Each file is expected to contain an
// optionally-newline-terminated PID of a running process.
class LockfileCheckerInterface {
 public:
  virtual ~LockfileCheckerInterface() = default;

  // Returns valid lockfiles.
  virtual std::vector<base::FilePath> GetValidLockfiles() const = 0;
};

class LockfileChecker : public LockfileCheckerInterface {
 public:
  // Lockfiles within |dir| or |files| will be honored.
  LockfileChecker(const base::FilePath& dir,
                  const std::vector<base::FilePath>& files);
  LockfileChecker(const LockfileChecker&) = delete;
  LockfileChecker& operator=(const LockfileChecker&) = delete;

  ~LockfileChecker() override;

  void set_proc_dir_for_test(const base::FilePath& dir) { proc_dir_ = dir; }

  // LockfileChecker:
  std::vector<base::FilePath> GetValidLockfiles() const override;

 private:
  // Directory used to check if PIDs exist (i.e. /proc; valid PIDs should be
  // represented by subdirs within this directory).
  base::FilePath proc_dir_;

  // Directory containing lockfiles.
  const base::FilePath dir_;

  // Legacy lockfiles outside of |dir_| that should also be checked.
  const std::vector<base::FilePath> files_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_LOCKFILE_CHECKER_H_
