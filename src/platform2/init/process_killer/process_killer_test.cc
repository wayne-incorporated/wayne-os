// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/process_killer/process_killer.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <init/process_killer/fake_process_manager.h>
#include <init/process_killer/process.h>
#include <init/process_killer/process_manager.h>

namespace init {

ActiveProcess GetInitProcess(pid_t pid, const std::string& comm) {
  return ActiveProcess(
      pid, true, comm,
      {{base::FilePath("/"), base::FilePath("/"), std::string("/dev/sda3")}},
      {{base::FilePath("/sbin/chromeos_startup")}});
}

ActiveProcess GetInitProcessWithLog(pid_t pid, const std::string& comm) {
  return ActiveProcess(
      pid, true, comm,
      {{base::FilePath("/"), base::FilePath("/"), std::string("/dev/sda3")}},
      {{base::FilePath("/var/log/init.log")}});
}

ActiveProcess GetEncstatefulProcess(pid_t pid,
                                    const std::string& comm,
                                    bool root_ns) {
  return ActiveProcess(pid, root_ns, comm,
                       {{base::FilePath("/var"), base::FilePath("/var"),
                         std::string("/dev/mapper/encstateful")}},
                       {{base::FilePath("/var/log/foo")}});
}

ActiveProcess GetEncstatefulProcessNoFilesOpen(pid_t pid,
                                               const std::string& comm,
                                               bool root_ns) {
  return ActiveProcess(pid, root_ns, comm,
                       {{base::FilePath("/var"), base::FilePath("/var"),
                         std::string("/dev/mapper/encstateful")}},
                       {{base::FilePath("/sbin/mount-encrypted")}});
}

ActiveProcess GetCryptohomeProcess(pid_t pid,
                                   const std::string& comm,
                                   bool root_ns) {
  return ActiveProcess(
      pid, root_ns, comm,
      {{base::FilePath("/user"), base::FilePath("/home/chronos/user"),
        std::string("/dev/mapper/dmcrypt-foo-data")}},
      {{base::FilePath("/home/chronos/user/foo")}});
}

TEST(ProcessKiller, SessionIrrelevantProcessTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting({GetInitProcess(1, "init")});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(true /*session*/, false /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, true);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 1);
}

TEST(ProcessKiller, ShutdownIrrelevantProcessTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting({GetInitProcess(1, "init")});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(false /*session*/, true /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, true);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 1);
}

TEST(ProcessKiller, DontKillInitTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting({GetInitProcessWithLog(1, "init")});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(false /*session*/, true /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, false);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 1);
}

TEST(ProcessKiller, SessionFileOpenTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting({GetCryptohomeProcess(5, "chrome", false)});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(true /*session*/, false /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, false);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 0);
}

TEST(ProcessKiller, SessionMountOpenTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting({GetCryptohomeProcess(5, "chrome", false)});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(true /*session*/, false /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(false, true);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 0);
}

TEST(ProcessKiller, ShutdownFileOpenTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting(
      {GetEncstatefulProcess(7, "dlcservice", false)});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(false /*session*/, true /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, false);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 0);
}

TEST(ProcessKiller, ShutdownMountOpenTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting(
      {GetEncstatefulProcessNoFilesOpen(7, "dlcservice", false)});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(false /*session*/, true /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(false, true);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 0);
}

TEST(ProcessKiller, ShutdownFileAndMountOpenTest) {
  std::unique_ptr<FakeProcessManager> pm =
      std::make_unique<FakeProcessManager>();
  FakeProcessManager* fake_pm = pm.get();
  fake_pm->SetProcessListForTesting(
      {GetEncstatefulProcess(7, "dlcservice", false)});

  std::unique_ptr<ProcessKiller> process_killer =
      std::make_unique<ProcessKiller>(false /*session*/, true /*shutdown*/);
  process_killer->SetProcessManagerForTesting(std::move(pm));
  process_killer->KillProcesses(true, true);

  EXPECT_EQ(fake_pm->GetProcessList(true, true).size(), 0);
}

}  // namespace init
