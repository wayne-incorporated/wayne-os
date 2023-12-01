// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for functionality in processes.h.

#include "secanomalyd/processes.h"

#include <map>
#include <optional>
#include <string>

#include <absl/strings/substitute.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>

#include <gtest/gtest.h>

#include <brillo/process/process_mock.h>

namespace secanomalyd::testing {

namespace {

const void ExpectEqProcEntry(const ProcEntry& actual_pe,
                             const ProcEntry& expected_pe) {
  EXPECT_EQ(actual_pe.pid(), expected_pe.pid());
  EXPECT_EQ(actual_pe.pidns(), expected_pe.pidns());
  EXPECT_EQ(actual_pe.mntns(), expected_pe.mntns());
  EXPECT_EQ(actual_pe.comm(), expected_pe.comm());
  EXPECT_EQ(actual_pe.args(), expected_pe.args());
  EXPECT_EQ(actual_pe.sandbox_status(), expected_pe.sandbox_status());
}

}  // namespace

class ProcessesTestFixture : public ::testing::Test {
  const std::string kStatusTemplate =
      "Name:	$0\n"
      "Umask:	0000\n"
      "State:	S (sleeping)\n"
      "Tgid:	1\n"
      "Ngid:	0\n"
      "Pid:	1\n"
      "PPid:	0\n"
      "TracerPid:	0\n"
      "Uid:	0	0	0	0\n"
      "Gid:	0	0	0	0\n"
      "FDSize:	123\n"
      "Groups:  20162 20164 20166\n"
      "NStgid:	1\n"
      "NSpid:	1\n"
      "NSpgid:	1\n"
      "NSsid:	1\n"
      "VmPeak:	1024 kB\n"
      "VmSize:	1024 kB\n"
      "VmLck:	0 kB\n"
      "VmPin:	0 kB\n"
      "VmHWM:	1234 kB\n"
      "VmRSS:	1234 kB\n"
      "RssAnon:	1234 kB\n"
      "RssFile:	1234 kB\n"
      "RssShmem:	0 kB\n"
      "VmData:	1234 kB\n"
      "VmStk:	123 kB\n"
      "VmExe:	123 kB\n"
      "VmLib:	1234 kB\n"
      "VmPTE:	24 kB\n"
      "VmSwap:	0 kB\n"
      "CoreDumping:	0\n"
      "THP_enabled:	1\n"
      "Threads:	1\n"
      "SigQ:	1/12345\n"
      "SigPnd:	0000000000000000\n"
      "ShdPnd:	0000000000000000\n"
      "SigBlk:	0000000000000000\n"
      "SigIgn:	0000000000001000\n"
      "SigCgt:	0000000012345678\n"
      "CapInh:	0000000000000000\n"
      "CapPrm:	000003ffffffffff\n"
      "CapEff:	000003ffffffffff\n"
      "CapBnd:	000003ffffffffff\n"
      "CapAmb:	0000000000000000\n"
      "NoNewPrivs:	$1\n"
      "Seccomp:	$2\n"
      "Seccomp_filters:	0\n"
      "Speculation_Store_Bypass:	vulnerable\n"
      "SpeculationIndirectBranch:	always enabled\n"
      "Cpus_allowed:	ff\n"
      "Cpus_allowed_list:	0-7\n"
      "Mems_allowed:	1\n"
      "Mems_allowed_list:	0\n"
      "voluntary_ctxt_switches:	1234\n"
      "nonvoluntary_ctxt_switches:	4321";

 public:
  MaybeProcEntries ReadMockProcesses() { return std::nullopt; }
  ProcEntry CreateMockProcEntry(pid_t pid,
                                ino_t pidns,
                                ino_t mntns,
                                std::string comm,
                                std::string args,
                                ProcEntry::SandboxStatus sandbox_status) {
    return ProcEntry(pid, pidns, mntns, comm, args, sandbox_status);
  }

 protected:
  struct MockProccess {
    std::string pid;
    std::string name;
    std::string no_new_privs;
    std::string seccomp;
    std::string cmdline;
    base::FilePath pid_ns_symlink;
    base::FilePath mnt_ns_symlink;
  };

  void CreateFakeProcfs(MockProccess& p, base::FilePath& pid_dir) {
    // Creates a pristine procfs for the process.
    ASSERT_TRUE(fake_root_.CreateUniqueTempDir());
    base::FilePath proc_dir = fake_root_.GetPath().Append("proc");
    ASSERT_TRUE(base::CreateDirectory(proc_dir));
    pid_dir = proc_dir.Append(p.pid);
    ASSERT_TRUE(base::CreateDirectory(pid_dir));

    // Generates content for the process status file, based on template.
    std::string status =
        absl::Substitute(kStatusTemplate, p.name, p.no_new_privs, p.seccomp);

    ASSERT_TRUE(base::WriteFile(pid_dir.Append("status"), status));
    ASSERT_TRUE(base::WriteFile(pid_dir.Append("cmdline"), p.cmdline));

    const base::FilePath ns_dir = pid_dir.Append("ns");
    ASSERT_TRUE(base::CreateDirectory(ns_dir));
    ASSERT_TRUE(
        base::CreateSymbolicLink(p.pid_ns_symlink, ns_dir.Append("pid")));
    ASSERT_TRUE(
        base::CreateSymbolicLink(p.mnt_ns_symlink, ns_dir.Append("mnt")));
  }

  void DestroyFakeProcfs() { ASSERT_TRUE(fake_root_.Delete()); }

  base::ScopedTempDir fake_root_;
  // Each key corresponds to the name of the test.
  std::map<std::string, MockProccess> mock_processes_ = {
      {"InitProcess",
       {
           .pid = "1",
           .name = "init",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = "/sbin/init",
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"NormalProcess",
       {
           .pid = "2",
           .name = "normal_process",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = std::string("normal_process\0--start", 22),
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"NormalProcessSecure",
       {
           .pid = "3",
           .name = "normal_process_secure",
           .no_new_privs = "1",
           .seccomp = "2",
           .cmdline = std::string("normal_process\0--start", 22),
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"EmptyCmdline",
       {
           .pid = "4",
           .name = "no_cmdline",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = "",
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"InvalidPIDNS",
       {
           .pid = "5",
           .name = "invalid_pidns",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = std::string("invalid_pidns\0--start", 21),
           .pid_ns_symlink = base::FilePath("abc"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"StatusReadFailure",
       {
           .pid = "6",
           .name = "status_read_failure",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = "",
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
      {"InvalidPID",
       {
           .pid = "abc",
           .name = "invalid_pid",
           .no_new_privs = "0",
           .seccomp = "0",
           .cmdline = std::string("invalid_pid\0--start", 19),
           .pid_ns_symlink = base::FilePath("pid:[402653184]"),
           .mnt_ns_symlink = base::FilePath("mnt:[402653184]"),
       }},
  };
};

TEST_F(ProcessesTestFixture, InitProcess) {
  std::string key = "InitProcess";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ProcEntry expected_pe =
      CreateMockProcEntry(1, 402653184, 402653184, mock_processes_[key].name,
                          mock_processes_[key].cmdline, 0b0000);
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  ASSERT_TRUE(actual_pe_ptr.has_value());
  ExpectEqProcEntry(actual_pe_ptr.value(), expected_pe);
}

TEST_F(ProcessesTestFixture, NormalProcess) {
  std::string key = "NormalProcess";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ProcEntry expected_pe =
      CreateMockProcEntry(2, 402653184, 402653184, mock_processes_[key].name,
                          "normal_process --start", 0b0000);
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  ASSERT_TRUE(actual_pe_ptr.has_value());
  ExpectEqProcEntry(actual_pe_ptr.value(), expected_pe);
}

TEST_F(ProcessesTestFixture, NormalProcessSecure) {
  std::string key = "NormalProcessSecure";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ProcEntry expected_pe =
      CreateMockProcEntry(3, 402653184, 402653184, mock_processes_[key].name,
                          "normal_process --start", 0b1010);
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  ASSERT_TRUE(actual_pe_ptr.has_value());
  ExpectEqProcEntry(actual_pe_ptr.value(), expected_pe);
}

TEST_F(ProcessesTestFixture, EmptyCmdline) {
  std::string key = "EmptyCmdline";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ProcEntry expected_pe =
      CreateMockProcEntry(4, 402653184, 402653184, mock_processes_[key].name,
                          "[" + mock_processes_[key].name + "]", 0b0000);
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  ASSERT_TRUE(actual_pe_ptr.has_value());
  ExpectEqProcEntry(actual_pe_ptr.value(), expected_pe);
}

TEST_F(ProcessesTestFixture, InvalidPIDNS) {
  std::string key = "InvalidPIDNS";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ProcEntry expected_pe =
      CreateMockProcEntry(5, 0, 402653184, mock_processes_[key].name,
                          "invalid_pidns --start", 0b0000);
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  ASSERT_TRUE(actual_pe_ptr.has_value());
  ExpectEqProcEntry(actual_pe_ptr.value(), expected_pe);
}

TEST_F(ProcessesTestFixture, StatusReadFailure) {
  std::string key = "StatusReadFailure";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  ASSERT_NO_FATAL_FAILURE(DestroyFakeProcfs());
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  EXPECT_EQ(actual_pe_ptr, std::nullopt);
}

TEST_F(ProcessesTestFixture, InvalidPID) {
  std::string key = "InvalidPID";
  base::FilePath pid_dir;
  ASSERT_NO_FATAL_FAILURE(CreateFakeProcfs(mock_processes_[key], pid_dir));
  MaybeProcEntry actual_pe_ptr = ProcEntry::CreateFromPath(pid_dir);
  EXPECT_EQ(actual_pe_ptr, std::nullopt);
}

}  // namespace secanomalyd::testing
