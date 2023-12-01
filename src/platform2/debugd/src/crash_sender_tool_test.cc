// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "debugd/src/crash_sender_tool.h"
#include "debugd/src/mock_process_with_id.h"

namespace debugd {
namespace {
using ::testing::_;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Pair;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StartsWith;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::UnorderedElementsAre;
using ::testing::Values;

constexpr char kCrashDirectoryStart[] = "--crash_directory=/proc/self/fd/";

class CrashSenderToolWithMockCreateProcess : public CrashSenderTool {
 public:
  ProcessWithId* CreateProcess(bool sandboxed,
                               bool allow_root_mount_ns) override {
    return &mock_process_;
  }

  MockProcessWithId& mock_process() { return mock_process_; }

  // Expect all the args that CrashSenderTool always adds to ProcessWithId
  // when it runs a process.
  void ExpectStandardArgs() {
    EXPECT_CALL(mock_process_, AddArg(_)).Times(0);
    EXPECT_CALL(mock_process_, AddArg("/sbin/crash_sender")).Times(1);
    EXPECT_CALL(mock_process_, AddArg("--max_spread_time=0")).Times(1);
    EXPECT_CALL(mock_process_, AddArg("--ignore_rate_limits")).Times(1);
  }

  // Expect all the args that CrashSenderTool uses when invoking from
  // UploadSingleCrash. Also, captures the argument to --crash_directory in
  // |crash_directory_arg|.
  void ExpectSingleCrashArgs(std::string* crash_directory_arg) {
    ExpectStandardArgs();
    EXPECT_CALL(mock_process_, AddArg("--ignore_hold_off_time")).Times(1);
    EXPECT_CALL(mock_process_, AddArg(StartsWith(kCrashDirectoryStart)))
        .WillOnce(SaveArg<0>(crash_directory_arg));
  }

  void ExpectSingleCrashAndConsentAlreadyCheckedArgs(
      std::string* crash_directory_arg) {
    ExpectStandardArgs();
    EXPECT_CALL(mock_process_, AddArg("--ignore_hold_off_time")).Times(1);
    EXPECT_CALL(mock_process_,
                AddArg("--consent_already_checked_by_crash_reporter"))
        .Times(1);
    EXPECT_CALL(mock_process_, AddArg(StartsWith(kCrashDirectoryStart)))
        .WillOnce(SaveArg<0>(crash_directory_arg));
  }

 private:
  MockProcessWithId mock_process_;
};

// Invoked during the call to mock_process_.Run(). Verifies that we were given
// a valid crash_directory argument, that the directory exists, and that the
// file descriptor points to the directory.
//
// |file_name_contents| will be filled in with file name + content pairs. Caller
// is responsible for using this to confirm that the correct set of files
// exists.
void VerifyStateInsideRun(
    const std::string& crash_directory_arg,
    const base::FilePath& expected_crash_directory,
    std::vector<std::pair<std::string, std::string>>* file_name_contents) {
  ASSERT_TRUE(base::DirectoryExists(expected_crash_directory));

  std::vector<std::string> actual_file_names;
  base::FileEnumerator file_list(
      expected_crash_directory, false,
      base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES);
  for (base::FilePath name = file_list.Next(); !name.empty();
       name = file_list.Next()) {
    auto info = file_list.GetInfo();
    EXPECT_FALSE(info.IsDirectory());
    std::string contents;
    EXPECT_TRUE(base::ReadFileToString(name, &contents));
    file_name_contents->emplace_back(name.value(), std::move(contents));
  }

  // crash_directory_arg should contain --crash_directory=/proc/self/fd/##,
  // where ## is a file descriptor that is open and reading /tmp/crash.1.
  ASSERT_GT(crash_directory_arg.size(), strlen(kCrashDirectoryStart));
  std::string fd_string =
      crash_directory_arg.substr(strlen(kCrashDirectoryStart));
  int fd = -1;
  ASSERT_TRUE(base::StringToInt(fd_string, &fd));
  struct stat stat_from_proc;
  int fstat_result = fstat(fd, &stat_from_proc);
  int saved_errno = errno;
  ASSERT_NE(fstat_result, -1) << "Error stating passing-in file descriptor: "
                              << base::safe_strerror(saved_errno);
  struct stat stat_from_tmp;
  int stat_result =
      stat(expected_crash_directory.value().c_str(), &stat_from_tmp);
  saved_errno = errno;
  ASSERT_NE(stat_result, -1)
      << "Error stating /tmp directory: " << base::safe_strerror(saved_errno);
  EXPECT_EQ(stat_from_tmp.st_dev, stat_from_proc.st_dev);
  EXPECT_EQ(stat_from_tmp.st_ino, stat_from_proc.st_ino);

  // In the real world, we would exec a new process during this call, so the
  // file descriptor must not be FD_CLOEXEC.
  int flags = fcntl(fd, F_GETFD);
  saved_errno = errno;
  EXPECT_NE(flags, -1) << "fnctl failed: " << base::safe_strerror(saved_errno);
  EXPECT_EQ(flags & FD_CLOEXEC, 0);
}

// Creates a temporary file and returns a file descriptor to it. The file will
// contain |contents|.
//
// Ideally, we would use memfd_create here instead of creating a file on disk
// (to better match the actual expected usage of UploadSingleCrash), but some
// unit test environments don't support memfd_create.
base::ScopedFD CreateFileWithContents(const std::string& contents) {
  base::FilePath temp_path;
  EXPECT_TRUE(GetTempDir(&temp_path));
  int fd =
      open(temp_path.value().c_str(), O_RDWR | O_TMPFILE, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    int saved_errno = errno;
    ADD_FAILURE() << "Could not open temp file: "
                  << base::safe_strerror(saved_errno);
    return base::ScopedFD();
  }

  int result = write(fd, contents.data(), contents.size());
  if (result == -1) {
    int saved_errno = errno;
    ADD_FAILURE() << "write to temp file: " << base::safe_strerror(saved_errno);
  } else if (result < contents.size()) {
    ADD_FAILURE() << "Partial write to temp file";
  }

  return base::ScopedFD(fd);
}
}  // namespace

TEST(UploadCrashes, CallsCrashSenderWithoutCrashDirectoryOrIgnoreHoldOffTime) {
  CrashSenderToolWithMockCreateProcess test_tool;

  // No arguments except standard ones.
  test_tool.ExpectStandardArgs();
  EXPECT_CALL(test_tool.mock_process(), Run()).WillOnce(Return(0));

  test_tool.UploadCrashes();
}

TEST(UploadSingleCrash, CreatesDirectory) {
  const base::FilePath kExpectedCrashDirectory("/tmp/crash.1");
  // Tests aren't as hermetic as we'd like; make sure that stale crash
  // directories aren't left over from previous failures.
  brillo::DeletePathRecursively(kExpectedCrashDirectory);

  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  brillo::ErrorPtr error;

  CrashSenderToolWithMockCreateProcess test_tool;
  std::string crash_directory_arg;
  test_tool.ExpectSingleCrashArgs(&crash_directory_arg);

  auto run_state_verifier = [&crash_directory_arg, &kExpectedCrashDirectory]() {
    std::vector<std::pair<std::string, std::string>> file_name_contents;
    VerifyStateInsideRun(crash_directory_arg, kExpectedCrashDirectory,
                         &file_name_contents);
    EXPECT_THAT(file_name_contents, IsEmpty());
    return 0;
  };

  EXPECT_CALL(test_tool.mock_process(), Run())
      .WillOnce(Invoke(run_state_verifier));

  EXPECT_TRUE(test_tool.UploadSingleCrash(
      files, &error, false /* consent_already_checked_by_crash_reporter */));
  EXPECT_EQ(error.get(), nullptr);

  // /tmp/crash.1 should now be deleted, and the file descriptor closed. We
  // don't check for the file descriptor being closed since some other part of
  // the system might have reused it.
  EXPECT_FALSE(base::PathExists(kExpectedCrashDirectory));
}

TEST(UploadSingleCrash, CreatesFilesInDirectory) {
  const base::FilePath kExpectedCrashDirectory("/tmp/crash.1");
  brillo::DeletePathRecursively(kExpectedCrashDirectory);

  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  constexpr char kFileAaaContents[] = "aaa";
  files.emplace_back("aaa.meta", CreateFileWithContents(kFileAaaContents));
  constexpr char kFileBbbContents[] = "123";
  files.emplace_back("bbb.version", CreateFileWithContents(kFileBbbContents));
  constexpr char kFileCccContents[] =
      "The quick brown fox jumped over the lazy dog.";
  files.emplace_back("ccc.log", CreateFileWithContents(kFileCccContents));
  brillo::ErrorPtr error;

  CrashSenderToolWithMockCreateProcess test_tool;
  std::string crash_directory_arg;
  test_tool.ExpectSingleCrashArgs(&crash_directory_arg);
  std::vector<std::pair<std::string, std::string>> file_name_contents;
  auto run_state_verifier = [&crash_directory_arg, &kExpectedCrashDirectory,
                             &file_name_contents]() {
    VerifyStateInsideRun(crash_directory_arg, kExpectedCrashDirectory,
                         &file_name_contents);
    return 0;
  };

  EXPECT_CALL(test_tool.mock_process(), Run())
      .WillOnce(Invoke(run_state_verifier));

  EXPECT_TRUE(test_tool.UploadSingleCrash(
      files, &error, false /* consent_already_checked_by_crash_reporter */));
  EXPECT_EQ(error.get(), nullptr);
  EXPECT_FALSE(base::PathExists(kExpectedCrashDirectory));

  EXPECT_THAT(
      file_name_contents,
      UnorderedElementsAre(Pair("/tmp/crash.1/aaa.meta", kFileAaaContents),
                           Pair("/tmp/crash.1/bbb.version", kFileBbbContents),
                           Pair("/tmp/crash.1/ccc.log", kFileCccContents)));
}

TEST(UploadSingleCrash, CreatesEmptyFile) {
  const base::FilePath kExpectedCrashDirectory("/tmp/crash.1");
  brillo::DeletePathRecursively(kExpectedCrashDirectory);

  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  files.emplace_back("empty", base::ScopedFD(memfd_create("empty", 0)));
  brillo::ErrorPtr error;

  CrashSenderToolWithMockCreateProcess test_tool;
  std::string crash_directory_arg;
  test_tool.ExpectSingleCrashArgs(&crash_directory_arg);
  std::vector<std::pair<std::string, std::string>> file_name_contents;
  auto run_state_verifier = [&crash_directory_arg, &kExpectedCrashDirectory,
                             &file_name_contents]() {
    VerifyStateInsideRun(crash_directory_arg, kExpectedCrashDirectory,
                         &file_name_contents);
    return 0;
  };

  EXPECT_CALL(test_tool.mock_process(), Run())
      .WillOnce(Invoke(run_state_verifier));

  EXPECT_TRUE(test_tool.UploadSingleCrash(
      files, &error, false /* consent_already_checked_by_crash_reporter */));
  EXPECT_EQ(error.get(), nullptr);
  EXPECT_FALSE(base::PathExists(kExpectedCrashDirectory));

  EXPECT_THAT(file_name_contents,
              UnorderedElementsAre(Pair("/tmp/crash.1/empty", "")));
}

TEST(UploadSingleCrash, CreatesLargeFilesCorrectly) {
  const base::FilePath kExpectedCrashDirectory("/tmp/crash.1");
  brillo::DeletePathRecursively(kExpectedCrashDirectory);

  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  std::string long_string;
  constexpr int kSize = 1 << 18;
  long_string.reserve(kSize);
  int i = 0;
  while (long_string.size() < kSize) {
    long_string += base::NumberToString(i);
    i++;
  }
  files.emplace_back("long.log", CreateFileWithContents(long_string));
  constexpr char kFileAaaContents[] = "aaa";
  files.emplace_back("aaa.meta", CreateFileWithContents(kFileAaaContents));
  brillo::ErrorPtr error;

  CrashSenderToolWithMockCreateProcess test_tool;
  std::string crash_directory_arg;
  test_tool.ExpectSingleCrashArgs(&crash_directory_arg);
  std::vector<std::pair<std::string, std::string>> file_name_contents;
  auto run_state_verifier = [&crash_directory_arg, &kExpectedCrashDirectory,
                             &file_name_contents]() {
    VerifyStateInsideRun(crash_directory_arg, kExpectedCrashDirectory,
                         &file_name_contents);
    return 0;
  };

  EXPECT_CALL(test_tool.mock_process(), Run())
      .WillOnce(Invoke(run_state_verifier));

  EXPECT_TRUE(test_tool.UploadSingleCrash(
      files, &error, false /* consent_already_checked_by_crash_reporter */));
  EXPECT_EQ(error.get(), nullptr);
  EXPECT_FALSE(base::PathExists(kExpectedCrashDirectory));

  EXPECT_THAT(
      file_name_contents,
      UnorderedElementsAre(Pair("/tmp/crash.1/aaa.meta", kFileAaaContents),
                           Pair("/tmp/crash.1/long.log", long_string)));
}

TEST(UploadSingleCrash, PassesConsentAlreadyCheckedCheckFlag) {
  // The directory /tmp/crash is specifically used for directories, and uses an
  // incrementing extension, so /tmp/crash.1 should be the first directory
  // selected to store crashes.
  const base::FilePath kExpectedCrashDirectory("/tmp/crash.1");
  // Tests aren't as hermetic as we'd like; make sure that stale crash
  // directories aren't left over from previous failures.
  brillo::DeletePathRecursively(kExpectedCrashDirectory);

  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  brillo::ErrorPtr error;

  CrashSenderToolWithMockCreateProcess test_tool;
  std::string crash_directory_arg;
  test_tool.ExpectSingleCrashAndConsentAlreadyCheckedArgs(&crash_directory_arg);

  EXPECT_TRUE(test_tool.UploadSingleCrash(
      files, &error, true /* consent_already_checked_by_crash_reporter */));
  EXPECT_EQ(error.get(), nullptr);

  // /tmp/crash.1 should now be deleted, and the file descriptor closed. We
  // don't check for the file descriptor being closed since some other part of
  // the system might have reused it.
  EXPECT_FALSE(base::PathExists(kExpectedCrashDirectory));
}

// Test that the filename given by the parameter will be rejected with a
// org.chromium.debugd.error.BadFileName error.
class BadFilenameTest : public TestWithParam<std::string> {
 public:
  BadFilenameTest() : file_name_(GetParam()) {}

 protected:
  // The bad file name. Taken from GetParam.
  const std::string file_name_;
};

TEST_P(BadFilenameTest, ReturnsBadFileNameError) {
  std::vector<std::tuple<std::string, base::ScopedFD>> files;
  files.emplace_back(file_name_, CreateFileWithContents("something"));
  brillo::ErrorPtr error;
  CrashSenderToolWithMockCreateProcess test_tool;

  // We should NOT run if there's a bad file name
  EXPECT_CALL(test_tool.mock_process(), Run()).Times(0);

  EXPECT_FALSE(test_tool.UploadSingleCrash(
      files, &error, false /* consent_already_checked_by_crash_reporter */));
  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetCode(), CrashSenderTool::kErrorBadFileName);
}

std::string FileNameToTestName(const TestParamInfo<std::string>& param) {
  // Result must be alphanumeric only. No _'s or other symbols, and no spaces.
  std::string result;
  for (char c : param.param) {
    switch (c) {
      case '/':
        result += "slash";
        break;
      case '.':
        result += "dot";
        break;
      default:
        if (base::IsAsciiAlpha(c) || base::IsAsciiDigit(c)) {
          result += c;
        } else {
          result += "something";
        }
        break;
    }
  }
  return result;
}

INSTANTIATE_TEST_SUITE_P(
    BadFilenameTests,
    BadFilenameTest,
    Values("/tmp/absolute", ".", "..", "../backup", "non/basename", "/", "//"),
    FileNameToTestName);

}  // namespace debugd
