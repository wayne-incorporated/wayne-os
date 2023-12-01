// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arcpp_cxx_collector.h"

#include <memory>
#include <unordered_map>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base/strings/strcat.h"
#include "crash-reporter/test_util.h"

using brillo::ClearLog;
using brillo::FindLog;
using brillo::GetLog;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::Return;

namespace {

const char k32BitAuxv[] = R"(
20 00 00 00 20 ba 7a ef 21 00 00 00 00 b0 7a ef
10 00 00 00 ff fb eb bf 06 00 00 00 00 10 00 00
11 00 00 00 64 00 00 00 03 00 00 00 34 d0 bb 5e
04 00 00 00 20 00 00 00 05 00 00 00 09 00 00 00
07 00 00 00 00 d0 7a ef 08 00 00 00 00 00 00 00
09 00 00 00 4d e6 bb 5e 0b 00 00 00 00 00 00 00
0c 00 00 00 00 00 00 00 0d 00 00 00 00 00 00 00
0e 00 00 00 00 00 00 00 17 00 00 00 01 00 00 00
19 00 00 00 3b 52 c6 ff 1f 00 00 00 de 6f c6 ff
0f 00 00 00 4b 52 c6 ff 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
)";

const char k64BitAuxv[] = R"(
21 00 00 00 00 00 00 00 00 30 db e6 fe 7f 00 00
10 00 00 00 00 00 00 00 ff fb eb bf 00 00 00 00
06 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00
11 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00
03 00 00 00 00 00 00 00 40 c0 a6 54 a5 5d 00 00
04 00 00 00 00 00 00 00 38 00 00 00 00 00 00 00
05 00 00 00 00 00 00 00 09 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00 00 10 3c 97 9c 7a 00 00
08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09 00 00 00 00 00 00 00 c8 de a6 54 a5 5d 00 00
0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
19 00 00 00 00 00 00 00 39 bc da e6 fe 7f 00 00
1f 00 00 00 00 00 00 00 de cf da e6 fe 7f 00 00
0f 00 00 00 00 00 00 00 49 bc da e6 fe 7f 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
)";

}  // namespace

class MockArcppCxxCollector : public ArcppCxxCollector {
 public:
  MockArcppCxxCollector() : ArcppCxxCollector() {}
  explicit MockArcppCxxCollector(ContextPtr context)
      : ArcppCxxCollector(std::move(context)) {}
  MOCK_METHOD(void, SetUpDBus, (), (override));
  MOCK_METHOD(ErrorType,
              ConvertCoreToMinidump,
              (pid_t pid,
               const base::FilePath&,
               const base::FilePath&,
               const base::FilePath&),
              (override));
};

class Test : public ::testing::Test {
 protected:
  void Initialize() {
    EXPECT_CALL(*collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_->Initialize(false, false);
    ClearLog();
  }

  std::unique_ptr<MockArcppCxxCollector> collector_;
};

class ArcppCxxCollectorTest : public Test {
 protected:
  class MockContext : public ArcppCxxCollector::Context {
   public:
    void SetArcPid(pid_t pid) { arc_pid_ = pid; }
    void AddProcess(pid_t pid,
                    const char* ns,
                    const char* exec,
                    const char* directory,
                    const char* cmd,
                    const char* auxv) {
      DCHECK_EQ(processes_.count(pid), 0u);
      DCHECK(ns);
      DCHECK(exec);
      auto& process = processes_[pid];
      process.ns = ns;
      process.exec = exec;
      process.directory = directory;
      process.cmd = cmd;
      process.auxv = auxv;
    }

   private:
    struct Process {
      const char* ns;
      const char* exec;
      const char* directory;
      const char* cmd;
      const char* auxv;
    };

    bool GetArcPid(pid_t* pid) const override {
      if (arc_pid_ == 0)
        return false;
      *pid = arc_pid_;
      return true;
    }
    bool GetPidNamespace(pid_t pid, std::string* ns) const override {
      const auto it = processes_.find(pid);
      if (it == processes_.end())
        return false;
      ns->assign(it->second.ns);
      return true;
    }
    bool GetExecBaseNameAndDirectory(
        pid_t pid,
        std::string* exec,
        base::FilePath* exec_directory) const override {
      const auto it = processes_.find(pid);
      if (it == processes_.end())
        return false;
      exec->assign(it->second.exec);
      *exec_directory = base::FilePath::FromASCII(it->second.directory);
      return true;
    }
    bool GetCommand(pid_t pid, std::string* command) const override {
      const auto it = processes_.find(pid);
      if (it == processes_.end())
        return false;
      const auto cmd = it->second.cmd;
      if (!cmd)
        return false;
      command->assign(cmd);
      return true;
    }
    bool ReadAuxvForProcess(pid_t pid, std::string* contents) const override {
      const auto it = processes_.find(pid);
      if (it == processes_.end())
        return false;
      const auto* auxv = it->second.auxv;
      if (!auxv)
        return false;
      std::istringstream ss(auxv);
      contents->clear();
      uint32_t byte;
      ss >> std::hex;
      while (ss >> byte) {
        contents->push_back(byte);
      }
      return true;
    }

    pid_t arc_pid_ = 0;
    std::unordered_map<pid_t, Process> processes_;
  };

  MockContext* context_;  // Owned by collector.
  base::FilePath test_dir_;
  base::FilePath crash_dir_;
  base::ScopedTempDir scoped_temp_dir_;

 private:
  void SetUp() override {
    context_ = new MockContext;
    collector_ = std::make_unique<MockArcppCxxCollector>(
        ArcppCxxCollector::ContextPtr(context_));

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    crash_dir_ = test_dir_.Append("crash_dir");
    ASSERT_TRUE(base::CreateDirectory(crash_dir_));
    collector_->set_crash_directory_for_test(crash_dir_);

    Initialize();
  }
};

class ArcContextTest : public Test {
 protected:
  pid_t pid_;

 private:
  void SetUp() override {
    collector_ = std::make_unique<MockArcppCxxCollector>();
    Initialize();
    pid_ = getpid();
  }
};

TEST_F(ArcppCxxCollectorTest, IsArcProcess) {
  EXPECT_FALSE(collector_->IsArcProcess(123));
  EXPECT_TRUE(FindLog("Failed to get PID of ARC container"));
  ClearLog();

  context_->SetArcPid(100);

  EXPECT_FALSE(collector_->IsArcProcess(123));
  EXPECT_TRUE(FindLog("Failed to get PID namespace of ARC container"));
  ClearLog();

  context_->AddProcess(100, "arc", "init", "/sbin", "/sbin/init", k32BitAuxv);

  EXPECT_FALSE(collector_->IsArcProcess(123));
  EXPECT_TRUE(FindLog("Failed to get PID namespace of process"));
  ClearLog();

  context_->AddProcess(50, "cros", "chrome", "/opt/google/chrome",
                       "/opt/google/chrome/chrome", k32BitAuxv);
  context_->AddProcess(123, "arc", "arc_service", "/sbin", "/sbin/arc_service",
                       k32BitAuxv);

  EXPECT_TRUE(collector_->IsArcProcess(123));
  EXPECT_TRUE(GetLog().empty());

  EXPECT_FALSE(collector_->IsArcProcess(50));
  EXPECT_TRUE(GetLog().empty());
}

TEST_F(ArcppCxxCollectorTest, GetExecBaseNameForUserCrash) {
  context_->SetArcPid(100);
  context_->AddProcess(100, "arc", "init", "/sbin", "/sbin/init", k32BitAuxv);
  context_->AddProcess(50, "cros", "chrome", "/opt/google/chrome",
                       "/opt/google/chrome/chrome", k32BitAuxv);

  std::string exec;
  base::FilePath exec_directory;
  EXPECT_TRUE(collector_->GetExecutableBaseNameAndDirectoryFromPid(
      50, &exec, &exec_directory));
  EXPECT_EQ("chrome", exec);
  EXPECT_EQ("/opt/google/chrome", exec_directory.value());
}

TEST_F(ArcppCxxCollectorTest, GetExecBaseNameForArcCrash) {
  context_->SetArcPid(100);
  context_->AddProcess(100, "arc", "init", "/sbin", "/sbin/init", k32BitAuxv);
  context_->AddProcess(123, "arc", "arc_service", "/sbin", "/sbin/arc_service",
                       k32BitAuxv);
  context_->AddProcess(456, "arc", "app_process32", "/sbin", nullptr,
                       k32BitAuxv);
  context_->AddProcess(789, "arc", "app_process32", "/sbin", "com.arc.app",
                       k32BitAuxv);

  std::string exec;
  base::FilePath exec_directory;

  EXPECT_TRUE(collector_->GetExecutableBaseNameAndDirectoryFromPid(
      123, &exec, &exec_directory));
  EXPECT_EQ("arc_service", exec);
  EXPECT_EQ("/sbin", exec_directory.value());

  EXPECT_TRUE(collector_->GetExecutableBaseNameAndDirectoryFromPid(
      456, &exec, &exec_directory));
  EXPECT_TRUE(FindLog("Failed to get package name"));
  EXPECT_EQ("app_process32", exec);
  EXPECT_EQ("/sbin", exec_directory.value());

  EXPECT_TRUE(collector_->GetExecutableBaseNameAndDirectoryFromPid(
      789, &exec, &exec_directory));
  EXPECT_EQ("com.arc.app", exec);
  EXPECT_EQ("/sbin", exec_directory.value());
}

TEST_F(ArcppCxxCollectorTest, ShouldDump) {
  context_->SetArcPid(100);
  context_->AddProcess(50, "cros", "chrome", "/opt/google/chrome",
                       "/opt/google/chrome/chrome", k32BitAuxv);
  context_->AddProcess(100, "arc", "init", "/sbin", "/sbin/init", k32BitAuxv);
  context_->AddProcess(123, "arc", "arc_service", "/sbin", "/sbin/arc_service",
                       k32BitAuxv);
  context_->AddProcess(789, "arc", "app_process32", "/sbin", "com.arc.app",
                       k32BitAuxv);

  std::string reason;
  EXPECT_FALSE(collector_->ShouldDump(50, 1234, "chrome", &reason));
  EXPECT_EQ("ignoring - crash origin is not ARC", reason);

  EXPECT_TRUE(collector_->ShouldDump(123, 0, "arc_service", &reason));
  EXPECT_EQ("handling", reason);

  EXPECT_FALSE(collector_->ShouldDump(123, ArcppCxxCollector::kSystemUserEnd,
                                      "com.arc.app", &reason));
  EXPECT_EQ("ignoring - not a system process", reason);
}

TEST_F(ArcppCxxCollectorTest, CorrectlyDetectBitness) {
  bool is_64_bit;

  context_->AddProcess(100, "arc", "app_process64", "/sbin", "zygote64",
                       k64BitAuxv);
  EXPECT_EQ(ArcppCxxCollector::kErrorNone,
            collector_->Is64BitProcess(100, &is_64_bit));
  EXPECT_TRUE(is_64_bit);

  context_->AddProcess(101, "arc", "app_process32", "/sbin", "zygote32",
                       k32BitAuxv);
  EXPECT_EQ(ArcppCxxCollector::kErrorNone,
            collector_->Is64BitProcess(101, &is_64_bit));
  EXPECT_FALSE(is_64_bit);
}

TEST_F(ArcContextTest, GetArcPid) {
  EXPECT_FALSE(ArcppCxxCollector::IsArcRunning());

  pid_t pid;
  EXPECT_FALSE(collector_->context().GetArcPid(&pid));
}

TEST_F(ArcppCxxCollectorTest, WritesMeta) {
  context_->SetArcPid(100);
  context_->AddProcess(100, "arc", "init", "/sbin", "/sbin/init", k32BitAuxv);
  context_->AddProcess(123, "arc", "arc_service", "/sbin", "/sbin/arc_service",
                       k32BitAuxv);

  EXPECT_CALL(
      *collector_,
      ConvertCoreToMinidump(123, base::FilePath("/tmp/crash_reporter/123"),
                            Property(&base::FilePath::value, EndsWith("core")),
                            Property(&base::FilePath::value, EndsWith("dmp"))))
      .WillOnce(Return(CrashCollector::kErrorNone));

  UserCollectorBase::CrashAttributes attrs;
  attrs.pid = 123;
  attrs.signal = 2;
  attrs.uid = 0;
  attrs.gid = 0;
  attrs.exec_name = "arc_service";
  EXPECT_TRUE(collector_->HandleCrash(attrs, nullptr));
  EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
      crash_dir_, "arc_service.*.123.meta", "exec_name=arc_service"));
}

TEST_F(ArcppCxxCollectorTest, GetArcPropertiesTestFullListP) {
  base::FilePath temp_file;
  arc_util::BuildProperty prop;

  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  ASSERT_TRUE(base::WriteFile(temp_file, base::StrCat({
                                             "  ",
                                             kBoardProperty,
                                             " =grunttest\n",
                                             " ",
                                             kCpuAbiProperty,
                                             "=x86_64\n",
                                             kDevicePropertyP,
                                             "=grunt_cheets\n",
                                             kFingerprintProperty,
                                             " =testfingerprintfoo\n",
                                         })));

  EXPECT_TRUE(GetArcProperties(temp_file, &prop));

  EXPECT_EQ("grunttest", prop.board);
  EXPECT_EQ("x86_64", prop.cpu_abi);
  EXPECT_EQ(prop.fingerprint, "testfingerprintfoo");
  EXPECT_EQ(prop.device, "grunt_cheets");
}

TEST_F(ArcppCxxCollectorTest, GetArcPropertiesTestFullListR) {
  base::FilePath temp_file;
  arc_util::BuildProperty prop;

  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  ASSERT_TRUE(base::WriteFile(temp_file, base::StrCat({
                                             " ",
                                             kBoardProperty,
                                             " =hanatest\n",
                                             kCpuAbiProperty,
                                             "  =arm64-v8a\n",
                                             kFingerprintProperty,
                                             "=testfingerprintbar\n",
                                             " ",
                                             kDevicePropertyR,
                                             " =hana_cheets\n",
                                         })));

  EXPECT_TRUE(GetArcProperties(temp_file, &prop));

  EXPECT_EQ("hanatest", prop.board);
  EXPECT_EQ("arm64-v8a", prop.cpu_abi);
  EXPECT_EQ(prop.fingerprint, "testfingerprintbar");
  EXPECT_EQ(prop.device, "hana_cheets");
}

TEST_F(ArcppCxxCollectorTest, GetArcPropertiesTestMissingItems) {
  base::FilePath temp_file;
  arc_util::BuildProperty prop;

  // Missing device property.
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  ASSERT_TRUE(base::WriteFile(temp_file, base::StrCat({
                                             kBoardProperty,
                                             " = hanatest\n",
                                             kCpuAbiProperty,
                                             "  =arm64-v8a\n",
                                             kFingerprintProperty,
                                             "=testfingerprintbar\n",
                                         })));

  EXPECT_FALSE(GetArcProperties(temp_file, &prop));

  // Missing board property.
  ASSERT_TRUE(base::WriteFile(temp_file, base::StrCat({
                                             kCpuAbiProperty,
                                             "  =arm64-v8a\n",
                                             kDevicePropertyR,
                                             " =hana_cheets\n",
                                             kFingerprintProperty,
                                             "=testfingerprintbaz\n",
                                         })));

  EXPECT_FALSE(GetArcProperties(temp_file, &prop));
}

TEST_F(ArcContextTest, GetPidNamespace) {
  std::string ns;
  EXPECT_TRUE(collector_->context().GetPidNamespace(pid_, &ns));
  EXPECT_THAT(ns, testing::MatchesRegex("^pid:\\[[0-9]+\\]$"));
}

TEST_F(ArcContextTest, GetExecBaseNameAndDirectory) {
  std::string exec;
  base::FilePath exec_directory;
  EXPECT_TRUE(collector_->context().GetExecBaseNameAndDirectory(
      pid_, &exec, &exec_directory));
  EXPECT_EQ("crash_reporter_test", exec);
  // Unit tests currently always run in
  // /var/cache/portage/chromeos-base/crash-reporter/out/Default. Make sure that
  // ArcppCxxCollector::Context::GetExecBaseNameAndDirectory gets the correct
  // directory. I chose the chromeos-base/crash-reporter substring as the least
  // likely to change out of those directory names.
  EXPECT_THAT(exec_directory.value(),
              HasSubstr("chromeos-base/crash-reporter"));
}

// TODO(crbug.com/590044)
TEST_F(ArcContextTest, DISABLED_GetCommand) {
  std::string command;
  EXPECT_TRUE(collector_->context().GetCommand(pid_, &command));

  // TODO(domlaskowski): QEMU mishandles emulation of /proc/self/cmdline,
  // prepending QEMU flags to the command line of the emulated program.
  // Keep in sync with qargv[1] in qemu-binfmt-wrapper.c for now.
  EXPECT_EQ("-0", command);
}
