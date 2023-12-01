// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/user_collector.h"

#include <bits/wordsize.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"
#include "crash-reporter/vm_support.h"
#include "crash-reporter/vm_support_mock.h"

using base::FilePath;
using brillo::FindLog;
using ::testing::_;
using ::testing::AllOf;
using ::testing::EndsWith;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Property;
using ::testing::Return;
using ::testing::StartsWith;

namespace {

const char kFilePath[] = "/my/path";

// Keep in sync with UserCollector::ShouldDump.
const char kChromeIgnoreMsg[] =
    "ignoring call by kernel - chrome crash; "
    "waiting for chrome to call us directly";

}  // namespace

class UserCollectorMock : public UserCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
  MOCK_METHOD(std::vector<std::string>,
              GetCommandLine,
              (pid_t),
              (const, override));
  MOCK_METHOD(void, AnnounceUserCrash, (), (override));
  MOCK_METHOD(ErrorType,
              ConvertCoreToMinidump,
              (pid_t pid,
               const base::FilePath&,
               const base::FilePath&,
               const base::FilePath&),
              (override));
};

class UserCollectorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    const std::vector<std::string> default_command_line = {"test_command",
                                                           "--test-arg"};
    EXPECT_CALL(collector_, GetCommandLine(testing::_))
        .WillRepeatedly(testing::Return(default_command_line));

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    paths::SetPrefixForTesting(test_dir_);

    const pid_t pid = getpid();
    collector_.Initialize(kFilePath, false, false, false);
    // Setup paths for output files.
    test_core_pattern_file_ = test_dir_.Append("core_pattern");
    collector_.set_core_pattern_file(test_core_pattern_file_.value());
    test_core_pipe_limit_file_ = test_dir_.Append("core_pipe_limit");
    collector_.set_core_pipe_limit_file(test_core_pipe_limit_file_.value());
    collector_.set_filter_path(test_dir_.Append("no_filter").value());
    crash_dir_ = test_dir_.Append("crash_dir");
    ASSERT_TRUE(base::CreateDirectory(crash_dir_));
    collector_.set_crash_directory_for_test(crash_dir_);
    pid_ = pid;

    brillo::ClearLog();
  }

  void TearDown() override { paths::SetPrefixForTesting(base::FilePath()); }

  void ExpectFileEquals(const char* golden, const FilePath& file_path) {
    std::string contents;
    EXPECT_TRUE(base::ReadFileToString(file_path, &contents));
    EXPECT_EQ(golden, contents);
  }

  std::vector<std::string> SplitLines(const std::string& lines) const {
    return base::SplitString(lines, "\n", base::KEEP_WHITESPACE,
                             base::SPLIT_WANT_ALL);
  }

  // Verify that the root directory is not writable. Several tests depend on
  // this fact, and are failing in ways that might be explained by having a
  // writable root directory.
  // Not using base::PathIsWritable because that doesn't actually check if the
  // user can write to a path :-/ See 'man 2 access'.
  static bool IsRootDirectoryWritable() {
    base::FilePath temp_file_path;
    if (!CreateTemporaryFileInDir(base::FilePath("/"), &temp_file_path)) {
      return false;
    }
    base::DeleteFile(temp_file_path);
    return true;
  }

  UserCollectorMock collector_;
  pid_t pid_;
  FilePath test_dir_;
  FilePath crash_dir_;
  FilePath test_core_pattern_file_;
  FilePath test_core_pipe_limit_file_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(UserCollectorTest, EnableOK) {
  ASSERT_TRUE(collector_.Enable(false));
  ExpectFileEquals("|/my/path --user=%P:%s:%u:%g:%f", test_core_pattern_file_);
  ExpectFileEquals("4", test_core_pipe_limit_file_);
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
}

TEST_F(UserCollectorTest, EnableNoPatternFileAccess) {
  // Basic checking:
  // Confirm we don't have junk left over from other tests.
  ASSERT_FALSE(base::PathExists(base::FilePath("/does_not_exist")));
  // We've seen strange problems that might be explained by having / writable.
  ASSERT_FALSE(IsRootDirectoryWritable());

  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Enable(false));
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, EnableNoPipeLimitFileAccess) {
  // Basic checking:
  // Confirm we don't have junk left over from other tests.
  ASSERT_FALSE(base::PathExists(base::FilePath("/does_not_exist")));
  // We've seen strange problems that might be explained by having / writable.
  ASSERT_FALSE(IsRootDirectoryWritable());

  collector_.set_core_pipe_limit_file("/does_not_exist");
  ASSERT_FALSE(collector_.Enable(false));
  // Core pattern should not be written if we cannot access the pipe limit
  // or otherwise we may set a pattern that results in infinite recursion.
  ASSERT_FALSE(base::PathExists(test_core_pattern_file_));
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, DisableOK) {
  ASSERT_TRUE(collector_.Disable());
  ExpectFileEquals("core", test_core_pattern_file_);
  EXPECT_TRUE(FindLog("Disabling user crash handling"));
}

TEST_F(UserCollectorTest, DisableNoFileAccess) {
  // Basic checking:
  // Confirm we don't have junk left over from other tests.
  ASSERT_FALSE(base::PathExists(base::FilePath("/does_not_exist")));
  // We've seen strange problems that might be explained by having / writable.
  ASSERT_FALSE(IsRootDirectoryWritable());

  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Disable());
  EXPECT_TRUE(FindLog("Disabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, ParseCrashAttributes) {
  std::optional<UserCollectorBase::CrashAttributes> attrs =
      UserCollectorBase::ParseCrashAttributes("123456:11:1000:2000:foobar");
  ASSERT_TRUE(attrs);
  EXPECT_EQ(123456, attrs->pid);
  EXPECT_EQ(11, attrs->signal);
  EXPECT_EQ(1000, attrs->uid);
  EXPECT_EQ(2000, attrs->gid);
  EXPECT_EQ("foobar", attrs->exec_name);

  attrs = UserCollectorBase::ParseCrashAttributes("4321:6:0:0:barfoo");
  ASSERT_TRUE(attrs);
  EXPECT_EQ(4321, attrs->pid);
  EXPECT_EQ(6, attrs->signal);
  EXPECT_EQ(0, attrs->uid);
  EXPECT_EQ(0, attrs->gid);
  EXPECT_EQ("barfoo", attrs->exec_name);

  EXPECT_FALSE(UserCollectorBase::ParseCrashAttributes("123456:11:1000"));
  EXPECT_FALSE(UserCollectorBase::ParseCrashAttributes("123456:11:1000:100"));

  attrs =
      UserCollectorBase::ParseCrashAttributes("123456:11:1000:100:exec:extra");
  ASSERT_TRUE(attrs);
  EXPECT_EQ("exec:extra", attrs->exec_name);

  EXPECT_FALSE(
      UserCollectorBase::ParseCrashAttributes("12345p:11:1000:100:foobar"));

  EXPECT_FALSE(
      UserCollectorBase::ParseCrashAttributes("123456:1 :1000:0:foobar"));

  EXPECT_FALSE(UserCollectorBase::ParseCrashAttributes("123456::::foobar"));
}

TEST_F(UserCollectorTest, ShouldDumpChromeOverridesDeveloperImage) {
  std::string reason;
  // When handle_chrome_crashes is false, should ignore chrome processes.
  EXPECT_FALSE(collector_.ShouldDump(pid_, false, "chrome", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "supplied_Compositor", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "supplied_PipelineThread", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "Chrome_ChildIOThread", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "supplied_Chrome_ChildIOT", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "supplied_ChromotingClien", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);
  EXPECT_FALSE(
      collector_.ShouldDump(pid_, false, "supplied_LocalInputMonit", &reason));
  EXPECT_EQ(kChromeIgnoreMsg, reason);

  // Test that chrome crashes are handled when the "handle_chrome_crashes" flag
  // is set.
  EXPECT_TRUE(collector_.ShouldDump(pid_, true, "chrome", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "supplied_Compositor", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "supplied_PipelineThread", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "Chrome_ChildIOThread", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "supplied_Chrome_ChildIOT", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "supplied_ChromotingClien", &reason));
  EXPECT_EQ("handling", reason);
  EXPECT_TRUE(
      collector_.ShouldDump(pid_, true, "supplied_LocalInputMonit", &reason));
  EXPECT_EQ("handling", reason);
}

TEST_F(UserCollectorTest, ShouldDumpUserConsentProductionImage) {
  std::string reason;

  EXPECT_TRUE(collector_.ShouldDump(pid_, false, "chrome-wm", &reason));
  EXPECT_EQ("handling", reason);
}

// HandleNonChromeCrashWithConsent tests that we will create a dmp file if we
// (a) have user consent to collect crash data and
// (b) the process is not a Chrome process.
TEST_F(UserCollectorTest, HandleNonChromeCrashWithConsent) {
  // Note the _ which is different from the - in the original |force_exec|
  // passed to HandleCrash. This is due to the CrashCollector::Sanitize call in
  // FormatDumpBasename.
  const std::string crash_prefix = crash_dir_.Append("chromeos_wm").value();
  int expected_mock_calls = 1;
  if (VmSupport::Get()) {
    expected_mock_calls = 0;
  }
  EXPECT_CALL(collector_, AnnounceUserCrash()).Times(expected_mock_calls);
  // NOTE: The '5' which appears in several strings below is the pid of the
  // simulated crashing process.
  EXPECT_CALL(collector_,
              ConvertCoreToMinidump(
                  5, FilePath("/tmp/crash_reporter/5"),
                  Property(&FilePath::value,
                           AllOf(StartsWith(crash_prefix), EndsWith("core"))),
                  Property(&FilePath::value,
                           AllOf(StartsWith(crash_prefix), EndsWith("dmp")))))
      .Times(expected_mock_calls)
      .WillRepeatedly(Return(CrashCollector::kErrorNone));

  UserCollectorBase::CrashAttributes attrs;
  attrs.pid = 5;
  attrs.signal = 2;
  attrs.uid = 1000;
  attrs.gid = 1000;
  attrs.exec_name = "ignored";
  EXPECT_TRUE(collector_.HandleCrash(attrs, "chromeos-wm"));
  if (!VmSupport::Get()) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
        crash_dir_, "chromeos_wm.*.meta", "exec_name=chromeos-wm"));
    EXPECT_TRUE(
        FindLog("Received crash notification for chromeos-wm[5] sig 2"));
  }
}

TEST_F(UserCollectorTest, HandleNonChromeCrashWithConsentAndSigsysNoSyscall) {
  // Note the _ which is different from the - in the original |force_exec|
  // passed to HandleCrash. This is due to the CrashCollector::Sanitize call in
  // FormatDumpBasename.
  const std::string crash_prefix = crash_dir_.Append("chromeos_wm").value();
  int expected_mock_calls = 1;
  if (VmSupport::Get()) {
    expected_mock_calls = 0;
  }
  EXPECT_CALL(collector_, AnnounceUserCrash()).Times(expected_mock_calls);
  // NOTE: The '5' which appears in several strings below is the pid of the
  // simulated crashing process.
  EXPECT_CALL(collector_,
              ConvertCoreToMinidump(
                  5, FilePath("/tmp/crash_reporter/5"),
                  Property(&FilePath::value,
                           AllOf(StartsWith(crash_prefix), EndsWith("core"))),
                  Property(&FilePath::value,
                           AllOf(StartsWith(crash_prefix), EndsWith("dmp")))))
      .Times(expected_mock_calls)
      .WillRepeatedly(Return(CrashCollector::kErrorNone));

  UserCollectorBase::CrashAttributes attrs;
  attrs.pid = 5;
  attrs.signal = SIGSYS;
  attrs.uid = 1000;
  attrs.gid = 1000;
  attrs.exec_name = "ignored";
  // Should succeed even without /proc/[pid]/syscall
  EXPECT_TRUE(collector_.HandleCrash(attrs, "chromeos-wm"));
  if (!VmSupport::Get()) {
    EXPECT_TRUE(test_util::DirectoryHasFileWithPatternAndContents(
        crash_dir_, "chromeos_wm.*.meta", "exec_name=chromeos-wm"));
    EXPECT_TRUE(
        FindLog("Received crash notification for chromeos-wm[5] sig 31"));
  }
}

// HandleChromeCrashWithConsent tests that we do not attempt to create a dmp
// file if the process is named chrome. This is because we expect Chrome's own
// crash handling library (Breakpad or Crashpad) to call us directly -- see
// chrome_collector.h.
TEST_F(UserCollectorTest, HandleChromeCrashWithConsent) {
  EXPECT_CALL(collector_, AnnounceUserCrash()).Times(0);
  EXPECT_CALL(collector_, ConvertCoreToMinidump(_, _, _, _)).Times(0);

  UserCollectorBase::CrashAttributes attrs;
  attrs.pid = 5;
  attrs.signal = 2;
  attrs.uid = 1000;
  attrs.gid = 1000;
  attrs.exec_name = "ignored";
  EXPECT_TRUE(collector_.HandleCrash(attrs, "chrome"));
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      crash_dir_, "chrome.*.meta", nullptr));
  if (!VmSupport::Get()) {
    EXPECT_TRUE(FindLog("Received crash notification for chrome[5] sig 2"));
    EXPECT_TRUE(FindLog(kChromeIgnoreMsg));
  }
}

// HandleSuppliedChromeCrashWithConsent also tests that we do not attempt to
// create a dmp file if the process is named chrome. This differs only in the
// fact that we are using the kernel's supplied name instead of the |force_exec|
// name. This is actually much closer to the real usage.
TEST_F(UserCollectorTest, HandleSuppliedChromeCrashWithConsent) {
  EXPECT_CALL(collector_, AnnounceUserCrash()).Times(0);
  EXPECT_CALL(collector_, ConvertCoreToMinidump(_, _, _, _)).Times(0);

  UserCollectorBase::CrashAttributes attrs;
  attrs.pid = 5;
  attrs.signal = 2;
  attrs.uid = 1000;
  attrs.gid = 1000;
  attrs.exec_name = "chrome";
  EXPECT_TRUE(collector_.HandleCrash(attrs, nullptr));
  EXPECT_FALSE(test_util::DirectoryHasFileWithPattern(
      crash_dir_, "chrome.*.meta", nullptr));
  if (!VmSupport::Get()) {
    EXPECT_TRUE(
        FindLog("Received crash notification for supplied_chrome[5] sig 2"));
    EXPECT_TRUE(FindLog(kChromeIgnoreMsg));
  }
}

TEST_F(UserCollectorTest, GetExecutableBaseNameFromPid) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());
  std::string base_name;
  base::FilePath exec_directory;
  EXPECT_FALSE(collector_.GetExecutableBaseNameAndDirectoryFromPid(
      0, &base_name, &exec_directory));
  EXPECT_TRUE(
      FindLog("ReadSymbolicLink failed - Path /proc/0 DirectoryExists: 0"));
  EXPECT_TRUE(FindLog("stat /proc/0/exe failed: -1 2"));

  brillo::ClearLog();
  pid_t my_pid = getpid();
  EXPECT_TRUE(collector_.GetExecutableBaseNameAndDirectoryFromPid(
      my_pid, &base_name, &exec_directory));
  EXPECT_FALSE(FindLog("Readlink failed"));
  EXPECT_EQ("crash_reporter_test", base_name);
  EXPECT_THAT(exec_directory.value(),
              HasSubstr("chromeos-base/crash-reporter"));
}

TEST_F(UserCollectorTest, GetFirstLineWithPrefix) {
  std::vector<std::string> lines;
  std::string line;

  EXPECT_FALSE(collector_.GetFirstLineWithPrefix(lines, "Name:", &line));
  EXPECT_EQ("", line);

  lines.push_back("Name:\tls");
  lines.push_back("State:\tR (running)");
  lines.push_back(" Foo:\t1000");

  line.clear();
  EXPECT_TRUE(collector_.GetFirstLineWithPrefix(lines, "Name:", &line));
  EXPECT_EQ(lines[0], line);

  line.clear();
  EXPECT_TRUE(collector_.GetFirstLineWithPrefix(lines, "State:", &line));
  EXPECT_EQ(lines[1], line);

  line.clear();
  EXPECT_FALSE(collector_.GetFirstLineWithPrefix(lines, "Foo:", &line));
  EXPECT_EQ("", line);

  line.clear();
  EXPECT_TRUE(collector_.GetFirstLineWithPrefix(lines, " Foo:", &line));
  EXPECT_EQ(lines[2], line);

  line.clear();
  EXPECT_FALSE(collector_.GetFirstLineWithPrefix(lines, "Bar:", &line));
  EXPECT_EQ("", line);
}

TEST_F(UserCollectorTest, GetIdFromStatus) {
  int id = 1;
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                          UserCollector::kIdEffective,
                                          SplitLines("nothing here"), &id));
  EXPECT_EQ(id, 1);

  // Not enough parameters.
  EXPECT_FALSE(
      collector_.GetIdFromStatus(UserCollector::kUserId, UserCollector::kIdReal,
                                 SplitLines("line 1\nUid:\t1\n"), &id));

  const std::vector<std::string> valid_contents =
      SplitLines("\nUid:\t1\t2\t3\t4\nGid:\t5\t6\t7\t8\n");
  EXPECT_TRUE(collector_.GetIdFromStatus(
      UserCollector::kUserId, UserCollector::kIdReal, valid_contents, &id));
  EXPECT_EQ(1, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdEffective,
                                         valid_contents, &id));
  EXPECT_EQ(2, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdFileSystem,
                                         valid_contents, &id));
  EXPECT_EQ(4, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kGroupId,
                                         UserCollector::kIdEffective,
                                         valid_contents, &id));
  EXPECT_EQ(6, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(
      UserCollector::kGroupId, UserCollector::kIdSet, valid_contents, &id));
  EXPECT_EQ(7, id);

  EXPECT_FALSE(collector_.GetIdFromStatus(
      UserCollector::kGroupId, UserCollector::IdKind(5), valid_contents, &id));
  EXPECT_FALSE(collector_.GetIdFromStatus(
      UserCollector::kGroupId, UserCollector::IdKind(-1), valid_contents, &id));

  // Fail if junk after number
  EXPECT_FALSE(
      collector_.GetIdFromStatus(UserCollector::kUserId, UserCollector::kIdReal,
                                 SplitLines("Uid:\t1f\t2\t3\t4\n"), &id));
  EXPECT_TRUE(
      collector_.GetIdFromStatus(UserCollector::kUserId, UserCollector::kIdReal,
                                 SplitLines("Uid:\t1\t2\t3\t4\n"), &id));
  EXPECT_EQ(1, id);

  // Fail if more than 4 numbers.
  EXPECT_FALSE(
      collector_.GetIdFromStatus(UserCollector::kUserId, UserCollector::kIdReal,
                                 SplitLines("Uid:\t1\t2\t3\t4\t5\n"), &id));
}

TEST_F(UserCollectorTest, GetStateFromStatus) {
  std::string state;
  EXPECT_FALSE(
      collector_.GetStateFromStatus(SplitLines("nothing here"), &state));
  EXPECT_EQ("", state);

  EXPECT_TRUE(
      collector_.GetStateFromStatus(SplitLines("State:\tR (running)"), &state));
  EXPECT_EQ("R (running)", state);

  EXPECT_TRUE(collector_.GetStateFromStatus(
      SplitLines("Name:\tls\nState:\tZ (zombie)\n"), &state));
  EXPECT_EQ("Z (zombie)", state);
}

TEST_F(UserCollectorTest, ClobberContainerDirectory) {
  // Try a path that is not writable.
  ASSERT_FALSE(collector_.ClobberContainerDirectory(FilePath("/bad/path")));
  EXPECT_TRUE(FindLog("Could not create /bad/path"));
}

TEST_F(UserCollectorTest, CopyOffProcFilesBadPid) {
  // Makes searching for the log string a little easier.
  paths::SetPrefixForTesting(base::FilePath());
  FilePath container_path = test_dir_.Append("container");
  ASSERT_TRUE(collector_.ClobberContainerDirectory(container_path));

  ASSERT_FALSE(collector_.CopyOffProcFiles(0, container_path));
  EXPECT_TRUE(FindLog("Path /proc/0 does not exist"));
}

TEST_F(UserCollectorTest, CopyOffProcFilesOK) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());
  FilePath container_path = test_dir_.Append("container");
  ASSERT_TRUE(collector_.ClobberContainerDirectory(container_path));

  ASSERT_TRUE(collector_.CopyOffProcFiles(pid_, container_path));
  EXPECT_FALSE(FindLog("Could not copy"));
  static const struct {
    const char* name;
    bool exists;
  } kExpectations[] = {
      {"auxv", true},   {"cmdline", true}, {"environ", true},
      {"maps", true},   {"mem", false},    {"mounts", false},
      {"sched", false}, {"status", true},  {"syscall", true},
  };
  for (const auto& expectation : kExpectations) {
    EXPECT_EQ(expectation.exists,
              base::PathExists(container_path.Append(expectation.name)));
  }
}

TEST_F(UserCollectorTest, GetRustSignature) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());

  int fd = memfd_create("RUST_PANIC_SIG", MFD_CLOEXEC);
  char dat[] = "Rust panic signature\nignored lines\n...";
  int count = strlen(dat);
  EXPECT_EQ(count, write(fd, dat, count));

  std::string panic_sig;
  bool success = collector_.GetRustSignature(pid_, &panic_sig);
  EXPECT_EQ(0, close(fd));

  ASSERT_TRUE(success);
  EXPECT_EQ("Rust panic signature", panic_sig);
}

TEST_F(UserCollectorTest, ValidateProcFiles) {
  FilePath container_dir = test_dir_;

  // maps file not exists (i.e. GetFileSize fails)
  EXPECT_FALSE(collector_.ValidateProcFiles(container_dir));

  // maps file is empty
  FilePath maps_file = container_dir.Append("maps");
  ASSERT_TRUE(test_util::CreateFile(maps_file, ""));
  ASSERT_TRUE(base::PathExists(maps_file));
  EXPECT_FALSE(collector_.ValidateProcFiles(container_dir));

  // maps file is not empty
  const char data[] = "test data";
  ASSERT_TRUE(test_util::CreateFile(maps_file, data));
  ASSERT_TRUE(base::PathExists(maps_file));
  EXPECT_TRUE(collector_.ValidateProcFiles(container_dir));
}

TEST_F(UserCollectorTest, ValidateCoreFile) {
  FilePath core_file = test_dir_.Append("core");

  // Core file does not exist
  EXPECT_EQ(UserCollector::kErrorReadCoreData,
            collector_.ValidateCoreFile(core_file));
  char e_ident[EI_NIDENT];
  e_ident[EI_MAG0] = ELFMAG0;
  e_ident[EI_MAG1] = ELFMAG1;
  e_ident[EI_MAG2] = ELFMAG2;
  e_ident[EI_MAG3] = ELFMAG3;
#if __WORDSIZE == 32
  e_ident[EI_CLASS] = ELFCLASS32;
#elif __WORDSIZE == 64
  e_ident[EI_CLASS] = ELFCLASS64;
#else
#error Unknown/unsupported value of __WORDSIZE.
#endif

  // Core file has the expected header
  ASSERT_TRUE(
      test_util::CreateFile(core_file, std::string(e_ident, sizeof(e_ident))));
  EXPECT_EQ(UserCollector::kErrorNone, collector_.ValidateCoreFile(core_file));

#if __WORDSIZE == 64
  // 32-bit core file on 64-bit platform
  e_ident[EI_CLASS] = ELFCLASS32;
  ASSERT_TRUE(
      test_util::CreateFile(core_file, std::string(e_ident, sizeof(e_ident))));
  EXPECT_EQ(UserCollector::kErrorUnsupported32BitCoreFile,
            collector_.ValidateCoreFile(core_file));
  e_ident[EI_CLASS] = ELFCLASS64;
#endif

  // Invalid core files
  ASSERT_TRUE(test_util::CreateFile(core_file,
                                    std::string(e_ident, sizeof(e_ident) - 1)));
  EXPECT_EQ(UserCollector::kErrorInvalidCoreFile,
            collector_.ValidateCoreFile(core_file));

  e_ident[EI_MAG0] = 0;
  ASSERT_TRUE(
      test_util::CreateFile(core_file, std::string(e_ident, sizeof(e_ident))));
  EXPECT_EQ(UserCollector::kErrorInvalidCoreFile,
            collector_.ValidateCoreFile(core_file));
}

TEST_F(UserCollectorTest, HandleSyscall) {
  const std::string exec = "placeholder";
  const std::string contents = std::to_string(SYS_read) + " col1 col2 col3";

  collector_.HandleSyscall(exec, contents);
  EXPECT_TRUE(
      base::Contains(collector_.extra_metadata_,
                     "seccomp_blocked_syscall_nr=" + std::to_string(SYS_read)));
  EXPECT_TRUE(base::Contains(collector_.extra_metadata_,
                             "seccomp_proc_pid_syscall=" + contents));
  EXPECT_TRUE(base::Contains(collector_.extra_metadata_,
                             std::string("seccomp_blocked_syscall_name=read")));
  EXPECT_TRUE(
      base::Contains(collector_.extra_metadata_,
                     std::string("sig=") + exec + "-seccomp-violation-read"));
}

struct CopyStdinToCoreFileTestParams {
  std::string test_name;
  std::string input;
  std::optional<std::string> existing_file_contents;
  bool handling_early_chrome_crash;
  bool in_loose_mode;
  bool expected_result;
  // std::nullopt means we expect the file to not exist.
  std::optional<std::string> expected_file_contents;
};

// Creates a string with the indicated number of characters. Does not have a
// repeating pattern so that missed pieces can be detected.
std::string StringOfSize(int size, base::StringPiece flavor_text) {
  std::string result;
  // Reserve enough room that the last loop doesn't need a reallocation. The
  // worst case is that the previous loop got us to size - 1, so we append
  // flavor_text and the textual representation of an int. If int is 64-bit,
  // the largest int is 9,223,372,036,854,775,807, which is 19 digits long.
  result.reserve((size - 1) + flavor_text.size() + 19);
  while (result.size() < size) {
    base::StrAppend(&result,
                    {flavor_text, base::NumberToString(result.size())});
  }
  return result.substr(0, size);
}

class CopyStdinToCoreFileTest
    : public UserCollectorTest,
      public testing::WithParamInterface<CopyStdinToCoreFileTestParams> {
 public:
  // Generate the list of tests to run.
  static std::vector<CopyStdinToCoreFileTestParams>
  GetCopyStdinToCoreFileTestParams();

 protected:
  // Writes |param.input| to the given file descriptor. Run on a different
  // thread so that we don't deadlock trying to both read and write a pipe on
  // one thread.
  static void WriteToFileDescriptor(CopyStdinToCoreFileTestParams params,
                                    base::ScopedFD write_fd) {
    LOG(INFO) << "Writing on thread " << base::PlatformThread::CurrentId();
    // Don't CHECK on the result. For the OversizedCore test, the write may
    // fail when the read side of the pipe closes.
    if (!base::WriteFileDescriptor(write_fd.get(), params.input.c_str())) {
      PLOG(WARNING) << "base::WriteFileDescriptor failed";
    }
  }

 private:
  // Needed for base::ThreadPool::PostDelayedTask to work. Must be in
  // MULTIPLE_THREADS mode. Important that this is destructed after the
  // local variable |read_fd|, so that the read side of the pipe closes and
  // base::WriteFileDescriptor gives up before we try to join the threads.
  base::test::TaskEnvironment task_env_;
};

// static
std::vector<CopyStdinToCoreFileTestParams>
CopyStdinToCoreFileTest::GetCopyStdinToCoreFileTestParams() {
  std::string kSmallCore = "Hello I am core";

  constexpr int kHalfChromeCoreSize = UserCollector::kMaxChromeCoreSize / 2;
  const std::string kHalfSizeCore =
      StringOfSize(kHalfChromeCoreSize, "Count it up");

  const std::string kMaxSizeCore =
      StringOfSize(UserCollector::kMaxChromeCoreSize, "Take it... to the max!");

  constexpr int kOversizedChromeCoreSize =
      3 * UserCollector::kMaxChromeCoreSize / 2;
  const std::string kOversizedChromeCore =
      StringOfSize(kOversizedChromeCoreSize, "MORE!!!");

  const std::string kPreexistingFileContents = "Haha, already a file here!";

  return {
      // In non-handling_early_chrome_crash_ mode, all cores should be accepted
      // and written out.
      CopyStdinToCoreFileTestParams{/*test_name=*/"NormalSmall",
                                    /*input=*/kSmallCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/false,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kSmallCore},
      CopyStdinToCoreFileTestParams{/*test_name=*/"NormalHalf",
                                    /*input=*/kHalfSizeCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/false,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kHalfSizeCore},
      CopyStdinToCoreFileTestParams{/*test_name=*/"NormalMax",
                                    /*input=*/kMaxSizeCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/false,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kMaxSizeCore},
      CopyStdinToCoreFileTestParams{
          /*test_name=*/"NormalOversize",
          /*input=*/kOversizedChromeCore,
          /*existing_file_contents=*/std::nullopt,
          /*handling_early_chrome_crash=*/false,
          /*in_loose_mode=*/false,
          /*expected_result=*/true,
          /*expected_file_contents=*/kOversizedChromeCore},
      // We remove the file on failure, even if it already existed, so
      // expected_file_contents is std::nullopt.
      CopyStdinToCoreFileTestParams{
          /*test_name=*/"NormalExistingFile",
          /*input=*/kSmallCore,
          /*existing_file_contents=*/kPreexistingFileContents,
          /*handling_early_chrome_crash=*/false,
          /*in_loose_mode=*/false,
          /*expected_result=*/false,
          /*expected_file_contents=*/std::nullopt},

      // In handling_early_chrome_crash_ mode, the oversized core should be
      // discarded.
      CopyStdinToCoreFileTestParams{/*test_name=*/"ChromeSmall",
                                    /*input=*/kSmallCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/true,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kSmallCore},
      CopyStdinToCoreFileTestParams{/*test_name=*/"ChromeHalf",
                                    /*input=*/kHalfSizeCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/true,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kHalfSizeCore},
      CopyStdinToCoreFileTestParams{/*test_name=*/"ChromeMax",
                                    /*input=*/kMaxSizeCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/true,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kMaxSizeCore},
      CopyStdinToCoreFileTestParams{/*test_name=*/"ChromeOversize",
                                    /*input=*/kOversizedChromeCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/true,
                                    /*in_loose_mode=*/false,
                                    /*expected_result=*/false,
                                    /*expected_file_contents=*/std::nullopt},
      CopyStdinToCoreFileTestParams{
          /*test_name=*/"ChromeExistingFile",
          /*input=*/kSmallCore,
          /*existing_file_contents=*/kPreexistingFileContents,
          /*handling_early_chrome_crash=*/true,
          /*in_loose_mode=*/false,
          /*expected_result=*/false,
          /*expected_file_contents=*/std::nullopt},

      // Loose mode tests: the oversized core should be accepted as well.
      CopyStdinToCoreFileTestParams{/*test_name=*/"ChromeLooseSmall",
                                    /*input=*/kSmallCore,
                                    /*existing_file_contents=*/std::nullopt,
                                    /*handling_early_chrome_crash=*/true,
                                    /*in_loose_mode=*/true,
                                    /*expected_result=*/true,
                                    /*expected_file_contents=*/kSmallCore},
      CopyStdinToCoreFileTestParams{
          /*test_name=*/"ChromeLooseOversize",
          /*input=*/kOversizedChromeCore,
          /*existing_file_contents=*/std::nullopt,
          /*handling_early_chrome_crash=*/true,
          /*in_loose_mode=*/true,
          /*expected_result=*/true,
          /*expected_file_contents=*/kOversizedChromeCore},
  };
}

INSTANTIATE_TEST_SUITE_P(
    CopyStdinToCoreFileTestSuite,
    CopyStdinToCoreFileTest,
    testing::ValuesIn(
        CopyStdinToCoreFileTest::GetCopyStdinToCoreFileTestParams()),
    [](const ::testing::TestParamInfo<CopyStdinToCoreFileTestParams>& info) {
      return info.param.test_name;
    });

TEST_P(CopyStdinToCoreFileTest, Test) {
  // Due to the difficulty of piping directly into stdin, we test a separate
  // function which has 99% of the code but which takes a pipe fd.
  CopyStdinToCoreFileTestParams params = GetParam();
  const base::FilePath kOutputPath = test_dir_.Append("output.txt");

  if (params.existing_file_contents) {
    ASSERT_TRUE(
        base::WriteFile(kOutputPath, params.existing_file_contents.value()));
  }

  if (params.in_loose_mode) {
    base::File::Error error;
    // Ensure util::IsReallyTestImage() returns true.
    const base::FilePath kFakeCrashReporterStateDirectory =
        paths::Get(paths::kCrashReporterStateDirectory);
    ASSERT_TRUE(base::CreateDirectoryAndGetError(
        kFakeCrashReporterStateDirectory, &error))
        << base::File::ErrorToString(error);
    const base::FilePath kLsbRelease =
        kFakeCrashReporterStateDirectory.Append(paths::kLsbRelease);
    ASSERT_TRUE(
        base::WriteFile(kLsbRelease, "CHROMEOS_RELEASE_TRACK=test-channel"));

    const base::FilePath kFakeRunStateDirectory =
        paths::Get(paths::kSystemRunStateDirectory);
    ASSERT_TRUE(
        base::CreateDirectoryAndGetError(kFakeRunStateDirectory, &error))
        << base::File::ErrorToString(error);
    const base::FilePath kLooseModeFile = kFakeRunStateDirectory.Append(
        paths::kRunningLooseChromeCrashEarlyTestFile);

    ASSERT_TRUE(test_util::CreateFile(kLooseModeFile, ""));
  }

  collector_.handling_early_chrome_crash_ = params.handling_early_chrome_crash;

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0) << strerror(errno);
  base::ScopedFD read_fd(pipefd[0]);
  base::ScopedFD write_fd(pipefd[1]);

  // Spin off another thread to do the writing, to avoid deadlocks on writing
  // to the pipe.
  LOG(INFO) << "Preparing to launch write thread from thread "
            << base::PlatformThread::CurrentId();
  base::ThreadPool::PostTask(
      FROM_HERE, base::BindOnce(&CopyStdinToCoreFileTest::WriteToFileDescriptor,
                                params, std::move(write_fd)));

  LOG(INFO) << "Starting read on thread " << base::PlatformThread::CurrentId();

  EXPECT_EQ(collector_.CopyPipeToCoreFile(read_fd.get(), kOutputPath),
            params.expected_result);

  if (params.expected_file_contents) {
    std::string file_contents;
    EXPECT_TRUE(base::ReadFileToString(kOutputPath, &file_contents));
    EXPECT_EQ(file_contents, params.expected_file_contents);
  } else {
    EXPECT_FALSE(base::PathExists(kOutputPath));
  }
}

TEST(UserCollectorNoFixtureTest, GuessChromeProductNameTest) {
  paths::SetPrefixForTesting(base::FilePath());
  struct Test {
    std::string input_directory;
    std::string expected_result;
    const char* log_message;
  };
  const Test kTests[] = {
      // Default ash-chrome location
      {"/opt/google/chrome", "Chrome_ChromeOS", nullptr},
      // Lacros in rootfs.
      {"/run/lacros", "Chrome_Lacros", nullptr},
      // Lacros in stateful, varies by channel.
      {"/run/imageloader/lacros-stable", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-beta", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-dev", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-canary", "Chrome_Lacros", nullptr},
      // Internal docs (go/crosep-lacros) suggest there might be a version
      // number in there as well. Probably obsolete but let's check.
      {"/run/imageloader/lacros-stable/101.0.4951.2", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-beta/101.0.4951.2", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-dev/101.0.4951.2", "Chrome_Lacros", nullptr},
      {"/run/imageloader/lacros-canary/101.0.4951.2", "Chrome_Lacros", nullptr},
      // Lacros during development.
      {"/usr/local/lacros-chrome", "Chrome_Lacros", nullptr},
      // If we couldn't get a directory, default to Chrome_ChromeOS.
      {"", "Chrome_ChromeOS", "Exectuable directory not known; assuming ash"},
      // Random directories default to Chrome_ChromeOS.
      {"/sbin", "Chrome_ChromeOS", "/sbin does not match Ash or Lacros paths"},
      {"/run/imageloader/cros-termina", "Chrome_ChromeOS",
       "/run/imageloader/cros-termina does not match Ash or Lacros paths"},
  };

  for (const Test& test : kTests) {
    brillo::ClearLog();
    EXPECT_EQ(UserCollector::GuessChromeProductName(
                  base::FilePath(test.input_directory)),
              test.expected_result)
        << " for " << test.input_directory;
    if (test.log_message == nullptr) {
      EXPECT_THAT(brillo::GetLog(), IsEmpty())
          << " for " << test.input_directory;
    } else {
      EXPECT_THAT(brillo::GetLog(), HasSubstr(test.log_message))
          << " for " << test.input_directory;
    }
  }
}

// Fixure for testing ShouldCaptureEarlyChromeCrash. Adds some extra setup
// that makes a basic fake set of /proc files, and has some extra functions
// to add other types of files.
class ShouldCaptureEarlyChromeCrashTest : public UserCollectorTest {
 protected:
  void SetUp() override {
    UserCollectorTest::SetUp();

    collector_.set_current_uptime_for_test(kCurrentUptime);

    CreateFakeProcess(kEarlyBrowserProcessID, 1, browser_cmdline_,
                      UserCollector::kNormalCmdlineSeparator,
                      base::Milliseconds(100));
    CreateFakeProcess(kEarlyRendererProcessID, kEarlyBrowserProcessID,
                      {"/opt/google/chrome/chrome", "--type=renderer",
                       "--log-level=1", "--enable-crashpad"},
                      UserCollector::kChromeSubprocessCmdlineSeparator,
                      base::Milliseconds(80));
    CreateFakeProcess(kNormalBrowserProcessID, 1, browser_cmdline_,
                      UserCollector::kNormalCmdlineSeparator,
                      base::Milliseconds(100));
    CreateFakeProcess(
        kCrashpadProcessID, kNormalBrowserProcessID,
        {"/opt/google/chrome/chrome_crashpad_handler", "--monitor-self",
         "--database=/var/log/chrome/Crash Reports"
         "--annotation=channel=unknown"},
        UserCollector::kNormalCmdlineSeparator, base::Milliseconds(90));
    CreateFakeProcess(
        kCrashpadChildProcessID, kCrashpadProcessID,
        {"/opt/google/chrome/chrome_crashpad_handler", "--no-periodic-tasks",
         "--database=/var/log/chrome/Crash Reports"
         "--annotation=channel=unknown"},
        UserCollector::kNormalCmdlineSeparator, base::Milliseconds(80));
    CreateFakeProcess(
        kNormalRendererProcessID, kNormalBrowserProcessID,
        {"/opt/google/chrome/chrome", "--log-level=1", "--enable-crashpad",
         "--crashpad-handler-pid=402", "--type=renderer"},
        UserCollector::kChromeSubprocessCmdlineSeparator,
        base::Milliseconds(80));
    CreateFakeProcess(kShillProcessID, 1, {"/usr/bin/shill", "--log-level=0"},
                      UserCollector::kNormalCmdlineSeparator,
                      base::Milliseconds(90));
  }

  base::FilePath GetProcessPath(pid_t pid) {
    return test_dir_.Append("proc").Append(base::NumberToString(pid));
  }

  // Given the argv cmdline that started a process, return the name that will
  // appear in /proc/pid/stat and /proc/pid/status.
  static std::string ProcNameFromCmdline(
      const std::vector<std::string>& cmdline) {
    CHECK(!cmdline.empty());
    base::FilePath exec_path(cmdline[0]);
    return exec_path.BaseName().value().substr(0, 15);
  }

  // Creates a fake /proc/|pid| record of a process inside
  // test_dir_.Append("proc"). Specifically creates:
  //  * the cmdline file.
  //  * the status file with Name, Pid, PPid fields filled in.
  //  * the stat file with the correct pid, name, ppid, and starttime (based on
  //    |age| parameter) fields.
  // CHECK-fails on failure.
  void CreateFakeProcess(pid_t pid,
                         pid_t parent_pid,
                         const std::vector<std::string>& cmdline,
                         char cmdline_separator,
                         base::TimeDelta age) {
    base::FilePath proc = GetProcessPath(pid);
    base::File::Error error;
    CHECK(base::CreateDirectoryAndGetError(proc, &error))
        << ": " << base::File::ErrorToString(error);

    base::File cmdline_file(proc.Append("cmdline"),
                            base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    CHECK(cmdline_file.IsValid())
        << ": " << base::File::ErrorToString(cmdline_file.error_details());

    for (const std::string& arg : cmdline) {
      CHECK_EQ(cmdline_file.WriteAtCurrentPos(arg.c_str(), arg.length()),
               arg.length());
      CHECK_EQ(cmdline_file.WriteAtCurrentPos(&cmdline_separator, 1), 1);
    }
    // Both Chrome and normal processes end with an extra \0.
    const char kNulByte = '\0';
    CHECK_EQ(cmdline_file.WriteAtCurrentPos(&kNulByte, 1), 1);

    std::string name = ProcNameFromCmdline(cmdline);
    // status file example from
    // https://man7.org/linux/man-pages/man5/proc.5.html, with just the fields
    // we care about as modified.
    std::string status_contents =
        base::StrCat({"Name:\t", name,
                      "\n"
                      "Umask:\t0022\n"
                      "State:\tS (sleeping)\n"
                      "Tgid:\t17248\n"
                      "Ngid:\t0\n"
                      "Pid:\t",
                      base::NumberToString(pid),
                      "\n"
                      "PPid:\t",
                      base::NumberToString(parent_pid),
                      "\n"
                      "TracerPid:\t0\n"
                      "Uid:\t1000\t1000\t1000\t1000\n"
                      "Gid:\t100\t100\t100\t100\n"
                      "FDSize:\t256\n"
                      "Groups:\t16 33 100\n"
                      "NStgid:\t17248\n"
                      "NSpid:\t17248\n"
                      "NSpgid:\t17248\n"
                      "NSsid:\t17200\n"
                      "VmPeak:\t    131168 kB\n"
                      "VmSize:\t    131168 kB\n"
                      "VmLck:\t          0 kB\n"
                      "VmPin:\t          0 kB\n"
                      "VmHWM:\t      13484 kB\n"
                      "VmRSS:\t      13484 kB\n"
                      "RssAnon:\t    10264 kB\n"
                      "RssFile:\t     3220 kB\n"
                      "RssShmem:\t       0 kB\n"
                      "VmData:\t     10332 kB\n"
                      "VmStk:\t        136 kB\n"
                      "VmExe:\t        992 kB\n"
                      "VmLib:\t       2104 kB\n"
                      "VmPTE:\t         76 kB\n"
                      "VmPMD:\t         12 kB\n"
                      "VmSwap:\t         0 kB\n"
                      "HugetlbPages:\t         0 kB\n"
                      "CoreDumping:\t  0\n"
                      "Threads:\t       1\n"
                      "SigQ:\t0/3067\n"
                      "SigPnd:\t0000000000000000\n"
                      "ShdPnd:\t0000000000000000\n"
                      "SigBlk:\t0000000000010000\n"
                      "SigIgn:\t0000000000384004\n"
                      "SigCgt:\t000000004b813efb\n"
                      "CapInh:\t0000000000000000\n"
                      "CapPrm:\t0000000000000000\n"
                      "CapEff:\t0000000000000000\n"
                      "CapBnd:\tffffffffffffffff\n"
                      "CapAmb:\t0000000000000000\n"
                      "NoNewPrivs:\t0\n"
                      "Seccomp:\t0\n"
                      "Speculation_Store_Bypass:\tvulnerable\n"
                      "Cpus_allowed:\t00000001\n"
                      "Cpus_allowed_list:\t0\n"
                      "Mems_allowed:\t1\n"
                      "Mems_allowed_list:\t0\n"
                      "voluntary_ctxt_switches:\t150\n"
                      "nonvoluntary_ctxt_switches:\t545\n"});
    CHECK(base::WriteFile(proc.Append("status"), status_contents));

    WriteProcStatFile(pid, cmdline, parent_pid, age);
  }

  // Writes the /proc/pid/stat file. Broken out as a separate function so that
  // tests can change the age easily. CHECK-fails on error.
  void WriteProcStatFile(pid_t pid,
                         const std::vector<std::string>& cmdline,
                         pid_t parent_pid,
                         base::TimeDelta age) {
    base::FilePath proc = GetProcessPath(pid);
    int starttime_in_ticks =
        (kCurrentUptime - age).InMilliseconds() * sysconf(_SC_CLK_TCK) / 1000;
    std::string name = ProcNameFromCmdline(cmdline);

    std::string stat_contents = base::StrCat(
        {base::NumberToString(pid), " (", name, ") S ",
         base::NumberToString(parent_pid),
         " 14895"    // pgrp
         " 14895"    // session
         " 34816"    // tty_nr
         " 20936"    // tpgid
         " 4194560"  // flags
         " 870"      // minflt
         " 2830"     // cminflt
         " 0"        // majflt
         " 1"        // cmajflt
         " 1"        // utime
         " 2"        // stime
         " 5"        // cutime
         " 11"       // cstime
         " 20"       // priority
         " 0"        // nice
         " 1"        // num_threads
         " 0 ",      // itrealvalue
         base::NumberToString(starttime_in_ticks),
         " 3731456 776 18446744073709551615 95057342971904 "
         "95057343528096 140723354001616 0 0 0 65536 3670020 1266777851 1 0 0 "
         "17 2 0 0 0 0 0 95057343548656 95057343556700 95057346277376 "
         "140723354005221 140723354005227 140723354005227 140723354005486 0"});
    CHECK(base::WriteFile(proc.Append("stat"), stat_contents));
  }

  // The fake pid of the browser process which is still in early startup.
  static constexpr pid_t kEarlyBrowserProcessID = 100;
  // The fake pid of the renderer process, which is the child of the browser
  // in early startup. (This isn't realistic, renderers wouldn't be started
  // before crashpad, but let's test anyways.)
  static constexpr pid_t kEarlyRendererProcessID = 102;
  // The fake pid of a different browser process which has a crashpad child
  // (and thus is not in early startup)
  static constexpr pid_t kNormalBrowserProcessID = 400;
  // The crashpad process that's a child of kNormalBrowserProcessID.
  static constexpr pid_t kCrashpadProcessID = 402;
  // The crashpad process that's a child of kCrashpadProcessID. (Crashpad
  // normally starts up two copies of crashpad, one to watch the other.)
  static constexpr pid_t kCrashpadChildProcessID = 403;
  // The fake pid of the renderer process, which is the child of the 'normal'
  // browser.
  static constexpr pid_t kNormalRendererProcessID = 407;
  // The fake pid of a shill process which has nothing to do with Chrome
  static constexpr pid_t kShillProcessID = 501;

  // The commandline we use for all the browser processes. The tests give all
  // our browser processes the same commandline so that the difference in test
  // results is purely because of the children (crashpad vs no crashpad).
  const std::vector<std::string> browser_cmdline_ = {
      "/opt/google/chrome/chrome", "--use-gl=egl", "--log-level=1",
      "--enable-crashpad", "--login-manager"};

  // The supposed amount of time the computer has been running when the test
  // takes place.
  static constexpr base::TimeDelta kCurrentUptime = base::Hours(10);
};

TEST_F(ShouldCaptureEarlyChromeCrashTest,
#if USE_FORCE_BREAKPAD
       DISABLED_BasicTrue
#else
       BasicTrue
#endif
) {
  EXPECT_TRUE(collector_.ShouldCaptureEarlyChromeCrash("chrome",
                                                       kEarlyBrowserProcessID));
  EXPECT_TRUE(collector_.ShouldCaptureEarlyChromeCrash("supplied_chrome",
                                                       kEarlyBrowserProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest,
#if USE_FORCE_BREAKPAD
       FalseIfBreakpad
#else
       DISABLED_FalseIfBreakpad
#endif
) {
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kEarlyBrowserProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "supplied_chrome", kEarlyBrowserProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest, FalseIfCrashpadIsChild) {
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kNormalBrowserProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest, FalseIfRenderer) {
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kEarlyRendererProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kNormalRendererProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest, FalseIfNonChrome) {
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome_crashpad_handler", kCrashpadProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome_crashpad_handler", kCrashpadChildProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest,
#if USE_FORCE_BREAKPAD
       DISABLED_BadProcFilesIgnored
#else
       BadProcFilesIgnored
#endif
) {
  // Give errors when reading some files inside /proc; this shouldn't stop us
  // from scanning the other proc files.
  base::FilePath early_renderer_status =
      GetProcessPath(kEarlyRendererProcessID).Append("status");
  CHECK(base::SetPosixFilePermissions(early_renderer_status, 0));

  base::FilePath crashpad_child_status =
      GetProcessPath(kCrashpadChildProcessID).Append("status");
  CHECK(base::WriteFile(crashpad_child_status, "Invalid junk"));

  // Same results as above:
  EXPECT_TRUE(collector_.ShouldCaptureEarlyChromeCrash("chrome",
                                                       kEarlyBrowserProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kNormalBrowserProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest, FalseIfTooOld) {
  // Overwrite age. Shouldn't change anything else.
  WriteProcStatFile(kEarlyBrowserProcessID, browser_cmdline_, 1,
                    base::Seconds(11));

  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome", kEarlyBrowserProcessID));
}

TEST_F(ShouldCaptureEarlyChromeCrashTest, FalseIfNotChrome) {
  EXPECT_FALSE(
      collector_.ShouldCaptureEarlyChromeCrash("nacl", kEarlyBrowserProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "chrome_crashpad", kEarlyBrowserProcessID));
  EXPECT_FALSE(collector_.ShouldCaptureEarlyChromeCrash(
      "supplied_chrome_crashpad", kEarlyBrowserProcessID));
  EXPECT_FALSE(
      collector_.ShouldCaptureEarlyChromeCrash("shill", kShillProcessID));
}

class BeginHandlingCrashTest : public ShouldCaptureEarlyChromeCrashTest {
 public:
  void SetUp() override {
    ShouldCaptureEarlyChromeCrashTest::SetUp();

#if USE_KVM_GUEST
    // Since we're not testing the VM support, just have the VM always return
    // true from ShouldDump.
    VmSupport::SetForTesting(&vm_support_mock_);
    ON_CALL(vm_support_mock_, ShouldDump(_, _)).WillByDefault(Return(true));
#endif
  }

  void TearDown() override {
    ShouldCaptureEarlyChromeCrashTest::TearDown();
#if USE_KVM_GUEST
    VmSupport::SetForTesting(nullptr);
#endif
  }

#if USE_KVM_GUEST
  VmSupportMock vm_support_mock_;
#endif
};

TEST_F(BeginHandlingCrashTest,
#if USE_FORCE_BREAKPAD
       DISABLED_SetsUpForEarlyChromeCrashes
#else
       SetsUpForEarlyChromeCrashes
#endif
) {
  collector_.BeginHandlingCrash(kEarlyBrowserProcessID, "chrome",
                                paths::Get("/opt/google/chrome"));

  // Ignored but we need something for ShouldDump().
  constexpr uid_t kUserUid = 1000;

  // We should be in early-chrome-crash mode, so ShouldDump should return true
  // even for a chrome executable.
  std::string reason;
  EXPECT_TRUE(collector_.ShouldDump(kEarlyBrowserProcessID, kUserUid, "chrome",
                                    &reason))
      << reason;

  EXPECT_THAT(collector_.get_extra_metadata_for_test(),
              AllOf(HasSubstr("upload_var_prod=Chrome_ChromeOS\n"),
                    HasSubstr("upload_var_early_chrome_crash=true\n"),
                    HasSubstr("upload_var_ptype=browser\n")));
}

TEST_F(BeginHandlingCrashTest, IgnoresNonEarlyBrowser) {
  collector_.BeginHandlingCrash(kNormalBrowserProcessID, "chrome",
                                paths::Get("/opt/google/chrome"));

  // Ignored but we need something for ShouldDump().
  constexpr uid_t kUserUid = 1000;

  std::string reason;
  EXPECT_FALSE(collector_.ShouldDump(kNormalBrowserProcessID, kUserUid,
                                     "chrome", &reason));

  EXPECT_THAT(collector_.get_extra_metadata_for_test(),
              AllOf(Not(HasSubstr("upload_var_prod=Chrome_ChromeOS\n")),
                    Not(HasSubstr("upload_var_early_chrome_crash=true\n")),
                    Not(HasSubstr("upload_var_ptype=browser\n"))));
}

TEST_F(BeginHandlingCrashTest, NoEffectIfNotChrome) {
  collector_.BeginHandlingCrash(kShillProcessID, "shill",
                                paths::Get("/usr/bin"));

  std::string reason;
  EXPECT_TRUE(collector_.ShouldDump(kShillProcessID, constants::kRootUid,
                                    "shill", &reason))
      << reason;

  EXPECT_THAT(collector_.get_extra_metadata_for_test(),
              AllOf(Not(HasSubstr("upload_var_prod=Chrome_ChromeOS\n")),
                    Not(HasSubstr("upload_var_early_chrome_crash=true\n")),
                    Not(HasSubstr("upload_var_ptype=browser\n"))));
}
