// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_MOCK_PROCESS_WITH_ID_H_
#define DEBUGD_SRC_MOCK_PROCESS_WITH_ID_H_

#include <stdint.h>

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "debugd/src/process_with_id.h"

namespace debugd {
class MockProcessWithId : public ProcessWithId {
 public:
  MOCK_METHOD(bool, Init, (), (override));
  MOCK_METHOD(bool, Init, (const std::vector<std::string>&), (override));
  MOCK_METHOD(void, DisableSandbox, (), (override));
  MOCK_METHOD(void,
              SandboxAs,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void, InheritUsergroups, (), (override));
  MOCK_METHOD(void, SetCapabilities, (uint64_t), (override));
  MOCK_METHOD(void,
              SetSeccompFilterPolicyFile,
              (const std::string&),
              (override));
  MOCK_METHOD(void, AllowAccessRootMountNamespace, (), (override));
  MOCK_METHOD(bool, KillProcessGroup, (), (override));
  MOCK_METHOD(void, AddArg, (const std::string&), (override));
  MOCK_METHOD(void, RedirectInput, (const std::string&), (override));
  MOCK_METHOD(void, RedirectOutput, (const std::string&), (override));
  MOCK_METHOD(void, RedirectUsingPipe, (int, bool), (override));
  MOCK_METHOD(void, BindFd, (int, int), (override));
  MOCK_METHOD(void, SetUid, (uid_t), (override));
  MOCK_METHOD(void, SetGid, (gid_t), (override));
  MOCK_METHOD(void, ApplySyscallFilter, (const std::string&), (override));
  MOCK_METHOD(void, EnterNewPidNamespace, (), (override));
  MOCK_METHOD(void, SetInheritParentSignalMask, (bool), (override));
  MOCK_METHOD(void, SetPreExecCallback, (PreExecCallback), (override));
  MOCK_METHOD(void, SetSearchPath, (bool), (override));
  MOCK_METHOD(int, GetPipe, (int), (override));
  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(int, Wait, (), (override));
  MOCK_METHOD(int, Run, (), (override));
  MOCK_METHOD(pid_t, pid, (), (override));
  MOCK_METHOD(bool, Kill, (int signal, int), (override));
  MOCK_METHOD(void, Reset, (pid_t), (override));
  MOCK_METHOD(bool, ResetPidByFile, (const std::string&), (override));
  MOCK_METHOD(pid_t, Release, (), (override));
  MOCK_METHOD(void, SetCloseUnusedFileDescriptors, (bool), (override));
};
}  // namespace debugd
#endif  // DEBUGD_SRC_MOCK_PROCESS_WITH_ID_H_
