// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SYSTEM_UTILS_IMPL_H_
#define LOGIN_MANAGER_SYSTEM_UTILS_IMPL_H_

#include "login_manager/system_utils.h"

#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

namespace base {
class FilePath;
}

namespace login_manager {

class SystemUtilsImpl : public SystemUtils {
 public:
  SystemUtilsImpl();
  SystemUtilsImpl(const SystemUtilsImpl&) = delete;
  SystemUtilsImpl& operator=(const SystemUtilsImpl&) = delete;

  ~SystemUtilsImpl() override;

  int kill(pid_t pid, uid_t owner, int signal) override;
  time_t time(time_t* t) override;
  pid_t fork() override;
  int close(int fd) override;
  int chdir(const base::FilePath& path) override;
  pid_t setsid() override;
  int execve(const base::FilePath& exec_file,
             const char* const argv[],
             const char* const envp[]) override;
  bool EnterNewMountNamespace() override;
  bool GetAppOutput(const std::vector<std::string>& argv,
                    std::string* output) override;
  DevModeState GetDevModeState() override;
  VmState GetVmState() override;
  bool ProcessGroupIsGone(pid_t child_spec, base::TimeDelta timeout) override;
  bool ProcessIsGone(pid_t child_spec, base::TimeDelta timeout) override;
  pid_t Wait(pid_t child_spec,
             base::TimeDelta timeout,
             int* status_out) override;

  bool EnsureAndReturnSafeFileSize(const base::FilePath& file,
                                   int32_t* file_size_32) override;
  bool Exists(const base::FilePath& file) override;
  bool DirectoryExists(const base::FilePath& dir) override;
  bool CreateDir(const base::FilePath& dir) override;
  bool EnumerateFiles(const base::FilePath& root_path,
                      int file_type,
                      std::vector<base::FilePath>* out_files) override;
  bool GetUniqueFilenameInWriteOnlyTempDir(
      base::FilePath* temp_file_path) override;
  bool RemoveFile(const base::FilePath& filename) override;
  bool AtomicFileWrite(const base::FilePath& filename,
                       const std::string& data) override;
  int64_t AmountOfFreeDiskSpace(const base::FilePath& path) override;
  bool GetGidAndGroups(uid_t uid,
                       gid_t* out_gid,
                       std::vector<gid_t>* out_groups) override;
  bool ReadFileToString(const base::FilePath& path,
                        std::string* str_out) override;
  bool WriteStringToFile(const base::FilePath& path,
                         const std::string& data) override;
  bool ChangeBlockedSignals(int how, const std::vector<int>& signals) override;
  bool LaunchAndWait(const std::vector<std::string>& args,
                     int* exit_code_out) override;
  bool RunInMinijail(const ScopedMinijail& jail,
                     const std::vector<std::string>& args,
                     const std::vector<std::string>& env_vars,
                     pid_t* pchild_pid) override;

  void set_base_dir_for_testing(const base::FilePath& base_dir) {
    CHECK(!base_dir.empty());
    CHECK(base_dir_for_testing_.empty());
    base_dir_for_testing_ = base_dir;
  }

  // Returns the given path "chrooted" inside |base_dir_for_testing_| if set.
  // Ex: /run/foo -> /tmp/.org.Chromium.whatever/run/foo
  base::FilePath PutInsideBaseDirForTesting(const base::FilePath& path);

 private:
  // Provides the real implementation of PutInsideBaseDirForTesting.
  base::FilePath PutInsideBaseDir(const base::FilePath& path);

  DevModeState dev_mode_state_ = DevModeState::DEV_MODE_UNKNOWN;
  VmState vm_state_ = VmState::UNKNOWN;
  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir_for_testing_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_SYSTEM_UTILS_IMPL_H_
