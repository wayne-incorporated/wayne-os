// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_SYSTEM_UTILS_H_
#define LOGIN_MANAGER_MOCK_SYSTEM_UTILS_H_

#include <stdint.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/macros.h>
#include <gmock/gmock.h>

#include "login_manager/system_utils.h"

namespace login_manager {

class MockSystemUtils : public SystemUtils {
 public:
  MockSystemUtils();
  MockSystemUtils(const MockSystemUtils&) = delete;
  MockSystemUtils& operator=(const MockSystemUtils&) = delete;

  ~MockSystemUtils() override;

  MOCK_METHOD(int, kill, (pid_t, uid_t, int), (override));
  MOCK_METHOD(time_t, time, (time_t*), (override));  // NOLINT
  MOCK_METHOD(pid_t, fork, (), (override));
  MOCK_METHOD(int, close, (int), (override));
  MOCK_METHOD(int, chdir, (const base::FilePath&), (override));
  MOCK_METHOD(pid_t, setsid, (), (override));
  MOCK_METHOD(int,
              execve,
              (const base::FilePath&, const char* const[], const char* const[]),
              (override));
  MOCK_METHOD(bool, EnterNewMountNamespace, (), (override));
  MOCK_METHOD(bool,
              GetAppOutput,
              (const std::vector<std::string>&, std::string*),
              (override));
  MOCK_METHOD(DevModeState, GetDevModeState, (), (override));
  MOCK_METHOD(VmState, GetVmState, (), (override));
  MOCK_METHOD(bool, ProcessGroupIsGone, (pid_t, base::TimeDelta), (override));
  MOCK_METHOD(bool, ProcessIsGone, (pid_t, base::TimeDelta), (override));
  MOCK_METHOD(pid_t, Wait, (pid_t, base::TimeDelta, int*), (override));
  MOCK_METHOD(bool,
              EnsureAndReturnSafeFileSize,
              (const base::FilePath&, int32_t*),
              (override));
  MOCK_METHOD(bool, Exists, (const base::FilePath&), (override));
  MOCK_METHOD(bool, DirectoryExists, (const base::FilePath&), (override));
  MOCK_METHOD(bool, CreateDir, (const base::FilePath&), (override));
  MOCK_METHOD(bool,
              EnumerateFiles,
              (const base::FilePath&, int, std::vector<base::FilePath>*),
              (override));
  MOCK_METHOD(bool,
              GetUniqueFilenameInWriteOnlyTempDir,
              (base::FilePath*),
              (override));
  MOCK_METHOD(bool, RemoveFile, (const base::FilePath&), (override));
  MOCK_METHOD(bool,
              AtomicFileWrite,
              (const base::FilePath&, const std::string&),
              (override));
  MOCK_METHOD(int64_t,
              AmountOfFreeDiskSpace,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              GetGidAndGroups,
              (uid_t, gid_t*, std::vector<gid_t>*),
              (override));

  MOCK_METHOD(bool,
              ReadFileToString,
              (const base::FilePath&, std::string*),
              (override));
  MOCK_METHOD(bool,
              WriteStringToFile,
              (const base::FilePath&, const std::string&),
              (override));

  MOCK_METHOD(bool,
              ChangeBlockedSignals,
              (int, const std::vector<int>&),
              (override));

  MOCK_METHOD(bool,
              LaunchAndWait,
              (const std::vector<std::string>&, int*),
              (override));
  MOCK_METHOD(bool,
              RunInMinijail,
              (const ScopedMinijail& jail,
               const std::vector<std::string>&,
               const std::vector<std::string>&,
               pid_t*),
              (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_SYSTEM_UTILS_H_
