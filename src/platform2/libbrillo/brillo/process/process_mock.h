// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_PROCESS_PROCESS_MOCK_H_
#define LIBBRILLO_BRILLO_PROCESS_PROCESS_MOCK_H_

#include <string>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include <brillo/process/process.h>

namespace brillo {

class ProcessMock : public Process {
 public:
  ProcessMock() {}
  virtual ~ProcessMock() {}

  MOCK_METHOD(void, AddArg, (const std::string&), (override));
  MOCK_METHOD(void, RedirectDevNull, (int), (override));
  MOCK_METHOD(void, RedirectInput, (const std::string&), (override));
  MOCK_METHOD(void, RedirectOutput, (const std::string&), (override));
  MOCK_METHOD(void, RedirectOutputToMemory, (bool), (override));
  MOCK_METHOD(void, RedirectUsingFile, (int, const std::string&), (override));
  MOCK_METHOD(void, RedirectUsingMemory, (int), (override));
  MOCK_METHOD(void, RedirectUsingPipe, (int, bool), (override));
  MOCK_METHOD(void, BindFd, (int, int), (override));
  MOCK_METHOD(void, SetUid, (uid_t), (override));
  MOCK_METHOD(void, SetGid, (gid_t), (override));
  MOCK_METHOD(void, SetPgid, (pid_t), (override));
  MOCK_METHOD(void, SetCapabilities, (uint64_t), (override));
  MOCK_METHOD(void, ApplySyscallFilter, (const std::string&), (override));
  MOCK_METHOD(void, EnterNewPidNamespace, (), (override));
  MOCK_METHOD(void, SetInheritParentSignalMask, (bool), (override));
  MOCK_METHOD(void, SetPreExecCallback, (PreExecCallback), (override));
  MOCK_METHOD(void, SetSearchPath, (bool), (override));
  MOCK_METHOD(int, GetOutputFd, (int), (override));
  MOCK_METHOD(std::string, GetOutputString, (int), (override));
  MOCK_METHOD(int, GetPipe, (int), (override));
  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(int, Wait, (), (override));
  MOCK_METHOD(int, Run, (), (override));
  MOCK_METHOD(pid_t, pid, (), (override));
  MOCK_METHOD(bool, Kill, (int, int), (override));
  MOCK_METHOD(void, Reset, (pid_t), (override));
  MOCK_METHOD(bool, ResetPidByFile, (const std::string&), (override));
  MOCK_METHOD(pid_t, Release, (), (override));
  MOCK_METHOD(void, SetCloseUnusedFileDescriptors, (bool), (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_PROCESS_PROCESS_MOCK_H_
