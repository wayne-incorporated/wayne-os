// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_collector_test.h"

#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/bind.h>
#include <base/test/simple_test_clock.h>
#include <base/test/task_environment.h>
#include <base/threading/platform_thread.h>
#include <base/threading/simple_thread.h>
#include <base/time/time.h>
#include <brillo/syslog_logging.h>
#include <dbus/object_path.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <policy/mock_device_policy.h>

#include "crash-reporter/crash_collector.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

using base::FilePath;
using base::StringPrintf;
using brillo::FindLog;
using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Optional;
using ::testing::Return;

// The QEMU emulator we use to run unit tests on simulated ARM boards does not
// support memfd_create. (https://bugs.launchpad.net/qemu/+bug/1734792) Skip
// tests that rely on memfd_create on ARM boards. (The tast test will still
// provide a basic check.)
#if defined(ARCH_CPU_ARM_FAMILY)
#define DISABLED_ON_QEMU_FOR_MEMFD_CREATE(test_name) DISABLED_##test_name
#else
#define DISABLED_ON_QEMU_FOR_MEMFD_CREATE(test_name) test_name
#endif

namespace {

// Fake "now" timestamp in milliseconds since Unix Epoch. Corresponds to
// Sept 1, 2020, but basically arbitrary.
constexpr int64_t kFakeNow = 1598929274543LL;

}  // namespace

CrashCollectorMock::CrashCollectorMock() : CrashCollector("mock") {}
CrashCollectorMock::CrashCollectorMock(
    CrashDirectorySelectionMethod crash_directory_selection_method,
    CrashSendingMode crash_sending_mode)
    : CrashCollector(
          "mock", crash_directory_selection_method, crash_sending_mode) {}

class CrashCollectorTest : public ::testing::Test {
 public:
  void SetUp() {
    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(Return());

    collector_.Initialize(false);

    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_dir_ = scoped_temp_dir_.GetPath();
    // TODO(jkardatzke): Cleanup the usage of paths in here so that we use this
    // technique instead rather than setting various specific dirs.
    paths::SetPrefixForTesting(test_dir_);

    brillo::ClearLog();
  }

  bool CheckHasCapacity();

  // Body of FinishCrashInCrashLoopModeSuccessfulResponse and
  // FinishCrashInCrashLoopModeErrorResponse.
  void TestFinishCrashInCrashLoopMode(bool give_success_response);

 protected:
  CrashCollectorMock collector_;
  FilePath test_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(CrashCollectorTest, ExtractEnvironmentVars_Regression) {
  constexpr const char raw_contents[] =
      "UPSTART_INSTANCE=\0INSTANCE=\0UPSTART_JOB=arcvm-forward-pstore\0TERM="
      "linux\0PATH=/usr/bin:/usr/sbin:/sbin:/bin:/usr/local/sbin:/usr/local/"
      "bin\0UPSTART_EVENTS=starting\0PWD=/"
      "\0JOB=arcvm-pre-login-services\0SECCOMP_POLICY_PATH=/usr/share/policy/"
      "arcvm-forward-pstore-seccomp.policy\0\0D_PRELOAD=/lib64/"
      "libminijailpreload.so\0\0_MINIJAIL_FD=3\0";
  std::ostringstream stream;
  std::string contents(raw_contents, sizeof(raw_contents));
  ExtractEnvironmentVars(contents, &stream);
  EXPECT_EQ(stream.str(),
            "SECCOMP_POLICY_PATH=/usr/share/policy/"
            "arcvm-forward-pstore-seccomp.policy\n");
}

// A variation on the above regression test where SECCOMP_POLICY_PATH is set
// after the double delimiter.
TEST_F(CrashCollectorTest, ExtractEnvironmentVars_DoubleDelimiter) {
  constexpr const char raw_contents[] =
      "UPSTART_INSTANCE=\0INSTANCE=\0UPSTART_JOB=arcvm-forward-pstore\0TERM="
      "linux\0PATH=/usr/bin:/usr/sbin:/sbin:/bin:/usr/local/sbin:/usr/local/"
      "bin\0UPSTART_EVENTS=starting\0PWD=/"
      "\0JOB=arcvm-pre-login-services\0\0D_PRELOAD=/lib64/"
      "libminijailpreload.so\0\0_MINIJAIL_FD=3\0SECCOMP_POLICY_PATH=/usr/share/"
      "policy/"
      "arcvm-forward-pstore-seccomp.policy\0";
  std::ostringstream stream;
  std::string contents(raw_contents, sizeof(raw_contents));
  ExtractEnvironmentVars(contents, &stream);
  EXPECT_EQ(stream.str(),
            "SECCOMP_POLICY_PATH=/usr/share/policy/"
            "arcvm-forward-pstore-seccomp.policy\n");
}

TEST_F(CrashCollectorTest, WriteNewFile) {
  FilePath test_file = test_dir_.Append("test_new");
  const char kBuffer[] = "buffer";
  EXPECT_EQ(strlen(kBuffer), collector_.WriteNewFile(test_file, kBuffer));
  EXPECT_EQ(collector_.get_bytes_written(), strlen(kBuffer));
  EXPECT_LT(collector_.WriteNewFile(test_file, kBuffer), 0);
  EXPECT_EQ(collector_.get_bytes_written(), strlen(kBuffer));
}

TEST_F(CrashCollectorTest, CopyToNewFile) {
  // Set up
  FilePath source_file = test_dir_.Append("test_source");
  const char expected_contents[] = "buffer";
  ASSERT_TRUE(base::WriteFile(source_file, expected_contents));
  base::File source(source_file, base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(source.IsValid());
  base::ScopedFD fd(source.TakePlatformFile());
  base::ScopedFD fd_dup(dup(fd.get()));
  ASSERT_TRUE(fd_dup.is_valid());

  // First copy should succeed and give expected contents
  FilePath target_file = test_dir_.Append("test_dest");
  EXPECT_TRUE(collector_.CopyFdToNewFile(std::move(fd), target_file));
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(target_file, &contents));
  EXPECT_EQ(contents, expected_contents);

  // Second copy should fail, and contents should remain.
  ASSERT_TRUE(base::WriteFile(source_file, "notbuffer_asdf"));
  EXPECT_FALSE(collector_.CopyFdToNewFile(std::move(fd_dup), target_file));
  ASSERT_TRUE(base::ReadFileToString(target_file, &contents));
  EXPECT_EQ(contents, expected_contents);
}

TEST_F(CrashCollectorTest, GetNewFileHandle) {
  FilePath source_file = test_dir_.Append("file");
  {
    base::ScopedFD fd = collector_.GetNewFileHandle(source_file);
    EXPECT_TRUE(fd.is_valid());
  }

  ASSERT_TRUE(base::WriteFile(source_file, ""));
  base::ScopedFD fd = collector_.GetNewFileHandle(source_file);
  EXPECT_FALSE(fd.is_valid());
}

TEST_F(CrashCollectorTest, GetNewFileHandle_Symlink) {
  FilePath source_file = test_dir_.Append("link");
  FilePath target_file = test_dir_.Append("target");
  ASSERT_TRUE(base::CreateSymbolicLink(target_file, source_file));
  base::ScopedFD fd = collector_.GetNewFileHandle(source_file);
  EXPECT_FALSE(fd.is_valid());
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(CrashLoopModeCreatesInMemoryFiles)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const char kBuffer[] = "Hello, this is buffer";
  const FilePath kPath = test_dir_.Append("buffer.txt");
  EXPECT_EQ(collector.WriteNewFile(kPath, kBuffer), strlen(kBuffer));

  auto result = collector.get_in_memory_files_for_test();
  ASSERT_EQ(result.size(), 1);
  EXPECT_EQ(std::get<0>(result[0]), "buffer.txt");
  base::File file(std::get<1>(result[0]).release());
  EXPECT_TRUE(file.IsValid());
  EXPECT_EQ(file.GetLength(), strlen(kBuffer));
  char result_buffer[100] = {'\0'};
  EXPECT_EQ(file.Read(0, result_buffer, sizeof(result_buffer)),
            strlen(kBuffer));
  EXPECT_EQ(std::string(kBuffer), std::string(result_buffer));
  // This should be an in-memory file, not a real file.
  EXPECT_FALSE(base::PathExists(kPath));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer));
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           CrashLoopModeCreatesMultipleInMemoryFiles)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const char kBuffer1[] = "Hello, this is buffer";
  const FilePath kPath1 = test_dir_.Append("buffer1.txt");
  EXPECT_EQ(collector.WriteNewFile(kPath1, kBuffer1), strlen(kBuffer1));

  const char kBuffer2[] = "Another buffer";
  const FilePath kPath2 = test_dir_.Append("buffer2.txt");
  EXPECT_EQ(collector.WriteNewFile(kPath2, kBuffer2), strlen(kBuffer2));

  const char kBuffer3[] = "Funny meme-ish text here";
  const FilePath kPath3 = test_dir_.Append("buffer3.txt");
  EXPECT_EQ(collector.WriteNewFile(kPath3, kBuffer3), strlen(kBuffer3));

  auto result = collector.get_in_memory_files_for_test();
  EXPECT_EQ(result.size(), 3);
  bool found1 = false;
  bool found2 = false;
  bool found3 = false;
  // Order doesn't matter as long as they're all there.
  for (int i = 0; i < 3; i++) {
    const char* expected_buffer = nullptr;
    if (std::get<0>(result[i]) == "buffer1.txt") {
      EXPECT_FALSE(found1);
      found1 = true;
      expected_buffer = kBuffer1;
    } else if (std::get<0>(result[i]) == "buffer2.txt") {
      EXPECT_FALSE(found2);
      found2 = true;
      expected_buffer = kBuffer2;
    } else {
      EXPECT_EQ(std::get<0>(result[i]), "buffer3.txt");
      EXPECT_FALSE(found3);
      found3 = true;
      expected_buffer = kBuffer3;
    }
    base::File file(std::get<1>(result[i]).release());
    EXPECT_TRUE(file.IsValid());
    EXPECT_EQ(file.GetLength(), strlen(expected_buffer));
    char result_buffer[100] = {'\0'};
    EXPECT_EQ(file.Read(0, result_buffer, sizeof(result_buffer)),
              strlen(expected_buffer));
    EXPECT_EQ(std::string(expected_buffer), std::string(result_buffer));
  }
  // These should be an in-memory files, not a real files.
  EXPECT_FALSE(base::PathExists(kPath1));
  EXPECT_FALSE(base::PathExists(kPath2));
  EXPECT_FALSE(base::PathExists(kPath3));
  EXPECT_EQ(collector.get_bytes_written(),
            strlen(kBuffer1) + strlen(kBuffer2) + strlen(kBuffer3));
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           CrashLoopModeWillNotCreateDuplicateFileNames)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath = test_dir_.Append("buffer.txt");
  const char kBuffer[] = "Hello, this is buffer";
  // First should succeed.
  EXPECT_EQ(collector.WriteNewFile(kPath, kBuffer), strlen(kBuffer));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer));

  // Second should fail.
  EXPECT_EQ(collector.WriteNewFile(kPath, kBuffer), -1);
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer));

  ASSERT_EQ(collector.get_in_memory_files_for_test().size(), 1);
}

TEST_F(CrashCollectorTest, CopyToNewCompressedFile) {
  FilePath source_file = test_dir_.Append("test_source");
  const char expected_contents[] = "uncompressed buffer contents";
  ASSERT_TRUE(base::WriteFile(source_file, expected_contents));
  base::File source(source_file, base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(source.IsValid());
  base::ScopedFD fd(source.TakePlatformFile());

  FilePath target_file = test_dir_.Append("test_dest.gz");
  EXPECT_TRUE(collector_.CopyFdToNewCompressedFile(std::move(fd), target_file));
  EXPECT_TRUE(base::PathExists(target_file));
  int64_t file_size = -1;
  EXPECT_TRUE(base::GetFileSize(target_file, &file_size));
  EXPECT_EQ(collector_.get_bytes_written(), file_size);

  int decompress_result = system(("gunzip " + target_file.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  FilePath test_file_uncompressed = target_file.RemoveFinalExtension();
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(test_file_uncompressed, &contents));
  EXPECT_EQ(expected_contents, contents);
}

TEST_F(CrashCollectorTest, CopyToNewCompressedFileFailsIfFileExists) {
  FilePath source_file = test_dir_.Append("test_source");
  const char expected_contents[] = "uncompressed buffer contents";
  ASSERT_TRUE(base::WriteFile(source_file, expected_contents));
  base::File source(source_file, base::File::FLAG_OPEN | base::File::FLAG_READ);
  ASSERT_TRUE(source.IsValid());
  base::ScopedFD fd(source.TakePlatformFile());

  FilePath target_file = test_dir_.Append("test_dest.gz");
  base::File touch_target_file(
      target_file, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  EXPECT_TRUE(touch_target_file.IsValid());
  touch_target_file.Close();

  EXPECT_FALSE(
      collector_.CopyFdToNewCompressedFile(std::move(fd), target_file));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(CrashCollectorTest, CopyToNewCompressedFileZeroSize) {
  FilePath source_file = test_dir_.Append("test_source");
  base::File source(source_file, base::File::FLAG_CREATE |
                                     base::File::FLAG_OPEN |
                                     base::File::FLAG_READ);
  ASSERT_TRUE(source.IsValid());
  base::ScopedFD fd(source.TakePlatformFile());

  FilePath target_file = test_dir_.Append("test_dest.gz");
  EXPECT_TRUE(collector_.CopyFdToNewCompressedFile(std::move(fd), target_file));
  EXPECT_TRUE(base::PathExists(target_file));
  int64_t file_size = -1;
  EXPECT_TRUE(base::GetFileSize(target_file, &file_size));
  EXPECT_EQ(collector_.get_bytes_written(), file_size);

  int decompress_result = system(("gunzip " + target_file.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  FilePath test_file_uncompressed = target_file.RemoveFinalExtension();
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(test_file_uncompressed, &contents));
  EXPECT_EQ(0, contents.length());
}

TEST_F(CrashCollectorTest, WriteNewCompressedFile) {
  FilePath test_file = test_dir_.Append("test_compressed_new.gz");
  const char kBuffer[] = "buffer";
  EXPECT_TRUE(
      collector_.WriteNewCompressedFile(test_file, kBuffer, strlen(kBuffer)));
  EXPECT_TRUE(base::PathExists(test_file));
  int64_t file_size = -1;
  EXPECT_TRUE(base::GetFileSize(test_file, &file_size));
  EXPECT_EQ(collector_.get_bytes_written(), file_size);

  int decompress_result = system(("gunzip " + test_file.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  FilePath test_file_uncompressed = test_file.RemoveFinalExtension();
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(test_file_uncompressed, &contents));
  EXPECT_EQ(kBuffer, contents);
}

TEST_F(CrashCollectorTest, WriteNewCompressedFileFailsIfFileExists) {
  FilePath test_file = test_dir_.Append("test_compressed_exist.gz");
  base::File touch_test_file(test_file,
                             base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  EXPECT_TRUE(touch_test_file.IsValid());
  touch_test_file.Close();

  const char kBuffer[] = "buffer";
  EXPECT_FALSE(
      collector_.WriteNewCompressedFile(test_file, kBuffer, strlen(kBuffer)));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           CrashLoopModeCreatesInMemoryCompressedFiles)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const char kBuffer[] = "Hello, this is buffer";
  const FilePath kPath = test_dir_.Append("buffer.txt.gz");
  EXPECT_TRUE(
      collector.WriteNewCompressedFile(kPath, kBuffer, strlen(kBuffer)));

  // This should be an in-memory file, not a real file.
  EXPECT_FALSE(base::PathExists(kPath));

  auto result = collector.get_in_memory_files_for_test();
  ASSERT_EQ(result.size(), 1);
  EXPECT_EQ(std::get<0>(result[0]), "buffer.txt.gz");
  base::File file(std::get<1>(result[0]).release());
  EXPECT_TRUE(file.IsValid());
  char compressed_result_buffer[100] = {'\0'};
  int read_amount =
      file.Read(0, compressed_result_buffer, sizeof(compressed_result_buffer));
  ASSERT_GT(read_amount, 0);
  EXPECT_EQ(collector.get_bytes_written(), read_amount);

  // Uncompress the data.
  base::FilePath uncompressed_path = test_dir_.Append("result.txt");
  base::FilePath compressed_path = uncompressed_path.AddExtension("gz");
  base::File compressed_file(compressed_path,
                             base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  EXPECT_TRUE(compressed_file.IsValid())
      << base::File::ErrorToString(compressed_file.error_details());
  EXPECT_EQ(compressed_file.Write(0, compressed_result_buffer, read_amount),
            read_amount);
  compressed_file.Close();
  int decompress_result = system(("gunzip " + compressed_path.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  std::string result_buffer;
  EXPECT_TRUE(base::ReadFileToString(uncompressed_path, &result_buffer));
  EXPECT_EQ(std::string(kBuffer), result_buffer);
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           CrashLoopModeWillNotCreateDuplicateCompressedFileNames)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath = test_dir_.Append("buffer.txt.gz");
  const char kBuffer[] = "Hello, this is buffer";
  // First should succeed.
  EXPECT_TRUE(
      collector.WriteNewCompressedFile(kPath, kBuffer, strlen(kBuffer)));
  EXPECT_GT(collector.get_bytes_written(), 0);
  off_t bytes_written_after_first = collector.get_bytes_written();

  // Second should fail.
  EXPECT_FALSE(
      collector.WriteNewCompressedFile(kPath, kBuffer, strlen(kBuffer)));
  EXPECT_EQ(collector.get_bytes_written(), bytes_written_after_first);

  ASSERT_EQ(collector.get_in_memory_files_for_test().size(), 1);
}

struct CopyFirstNBytesTestParams {
  std::string test_name;
  std::string input;
  int bytes_to_copy;
  std::string expected_output;
  int expected_bytes_written;
  base::TimeDelta write_delay;
  base::TimeDelta read_delay;
  int write_chunks;
};

std::vector<CopyFirstNBytesTestParams> GetCopyFirstNBytesTestParams() {
  const std::string kShortString = "Hello World And Everything Else";
  constexpr int kLongStringLen = 40 * 1024 * 1024;
  std::string long_string;
  long_string.reserve(kLongStringLen);

  // Generate a string without a repeating pattern.
  while (long_string.size() < kLongStringLen) {
    base::StrAppend(&long_string, {base::NumberToString(long_string.size())});
  }
  long_string = long_string.substr(0, kLongStringLen);

  std::vector<CopyFirstNBytesTestParams> results;
  enum StrLength { kShort, kLong };
  for (StrLength len : {kShort, kLong}) {
    std::string prefix = (len == kShort ? "Short" : "Long");
    std::string input = (len == kShort ? kShortString : long_string);
    int input_length = static_cast<int>(input.size());
    std::string first_half_of_input = input.substr(0, input_length / 2);
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "FastComplete"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length * 2,
        /*expected_output=*/input,
        /*expected_bytes_written=*/input_length,
        /*write_delay=*/base::TimeDelta(),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "FastExactBytes"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length,
        /*expected_output=*/input,
        /*expected_bytes_written=*/input_length,
        /*write_delay=*/base::TimeDelta(),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "FastTruncated"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length / 2,
        /*expected_output=*/first_half_of_input,
        /*expected_bytes_written=*/input_length / 2,
        /*write_delay=*/base::TimeDelta(),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "WriteFirst"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length * 2,
        /*expected_output=*/input,
        /*expected_bytes_written=*/input_length,
        /*write_delay=*/base::TimeDelta(),
        /*read_delay=*/base::Milliseconds(200),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "ReadFirst"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length * 2,
        /*expected_output=*/input,
        /*expected_bytes_written=*/input_length,
        /*write_delay=*/base::Milliseconds(200),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "WriteFirstTruncated"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length / 2,
        /*expected_output=*/first_half_of_input,
        /*expected_bytes_written=*/input_length / 2,
        /*write_delay=*/base::TimeDelta(),
        /*read_delay=*/base::Milliseconds(200),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "ReadFirstTruncated"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length / 2,
        /*expected_output=*/first_half_of_input,
        /*expected_bytes_written=*/input_length / 2,
        /*write_delay=*/base::Milliseconds(200),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/1});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "ChunkedComplete"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length * 2,
        /*expected_output=*/input,
        /*expected_bytes_written=*/input_length,
        /*write_delay=*/base::Milliseconds(200),
        /*read_delay=*/base::TimeDelta(),
        /*write_chunks=*/3});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "ChunkedTruncated3"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length / 2,
        /*expected_output=*/first_half_of_input,
        /*expected_bytes_written=*/input_length / 2,
        /*write_delay=*/base::Milliseconds(200),
        /*read_delay=*/base::TimeDelta(),
        // write_chunks is 3 so that we pick up half of one chunk.
        /*write_chunks=*/3});
    results.push_back(CopyFirstNBytesTestParams{
        /*test_name=*/base::StrCat({prefix, "ChunkedTruncated4"}),
        /*input=*/input,
        /*bytes_to_copy=*/input_length / 2,
        /*expected_output=*/first_half_of_input,
        /*expected_bytes_written=*/input_length / 2,
        /*write_delay=*/base::Milliseconds(200),
        /*read_delay=*/base::TimeDelta(),
        // write_chunks is 4 so that we get a complete chunk and then nothing
        // from the next chunk.
        /*write_chunks=*/4});
  }

  results.push_back(CopyFirstNBytesTestParams{
      /*test_name=*/"EmptyInput",
      /*input=*/"Won't be written because of write_chunks = 0",
      /*bytes_to_copy=*/20,
      /*expected_output=*/"",
      /*expected_bytes_written=*/0,
      /*write_delay=*/base::TimeDelta(),
      /*read_delay=*/base::TimeDelta(),
      // write_chunks of 0 will close the write side of the pipe without writing
      // anything to the file.
      /*write_chunks=*/0});
  return results;
}

class CopyFirstNBytesParameterizedTest
    : public CrashCollectorTest,
      public testing::WithParamInterface<CopyFirstNBytesTestParams> {
 protected:
  // Writes |params.input| to the given file descriptor. Run on a different
  // thread so that we don't deadlock trying to both read and write a pipe on
  // one thread.
  static void WriteToFileDescriptor(CopyFirstNBytesTestParams params,
                                    base::ScopedFD write_fd) {
    for (int chunk_index = 0; chunk_index < params.write_chunks;
         chunk_index++) {
      int start = (params.input.length() * chunk_index) / params.write_chunks;
      // end in the classic STL sense -- one past the last character in the
      // chunk.
      int end =
          (params.input.length() * (chunk_index + 1)) / params.write_chunks;
      std::string chunk = params.input.substr(start, end - start);
      LOG(INFO) << "Writing chunk " << chunk_index << " [" << start << "-"
                << end << ") on thread " << base::PlatformThread::CurrentId();
      // Don't CHECK on the result. For the Truncated tests, the writes will
      // often fail when the read side closes the file descriptor.
      if (!base::WriteFileDescriptor(write_fd.get(), chunk.c_str())) {
        PLOG(WARNING) << "base::WriteFileDescriptor failed for chunk "
                      << chunk_index;
        break;
      }

      if (chunk_index < params.write_chunks - 1) {
        base::PlatformThread::Sleep(base::Milliseconds(200));
      }
    }
  }

 private:
  // Needed for base::ThreadPool::PostDelayedTask to work. Must be in
  // MULTIPLE_THREADS mode. Important that this is destructed after the
  // local variable |read_fd|, so that the read side of the pipe closes and
  // base::WriteFileDescriptor gives up before we try to join the threads.
  base::test::TaskEnvironment task_env_;
};

INSTANTIATE_TEST_SUITE_P(
    CopyFirstNBytesSuite,
    CopyFirstNBytesParameterizedTest,
    testing::ValuesIn(GetCopyFirstNBytesTestParams()),
    [](const ::testing::TestParamInfo<CopyFirstNBytesTestParams>& info) {
      return info.param.test_name;
    });

TEST_P(CopyFirstNBytesParameterizedTest, CopyFirstNBytes) {
  const FilePath kOutputPath = test_dir_.Append("output.txt");
  CopyFirstNBytesTestParams params = GetParam();

  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0) << strerror(errno);
  base::ScopedFD read_fd(pipefd[0]);
  base::ScopedFD write_fd(pipefd[1]);

  // Spin off another thread to do the writing, to avoid deadlocks on writing
  // to the pipe.
  LOG(INFO) << "Preparing to launch write thread from thread "
            << base::PlatformThread::CurrentId();
  base::ThreadPool::PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&CopyFirstNBytesParameterizedTest::WriteToFileDescriptor,
                     params, std::move(write_fd)),
      params.write_delay);

  if (params.read_delay.is_positive()) {
    base::PlatformThread::Sleep(params.read_delay);
  }

  LOG(INFO) << "Starting read on thread " << base::PlatformThread::CurrentId();

  EXPECT_THAT(collector_.CopyFirstNBytesOfFdToNewFile(
                  read_fd.get(), kOutputPath, params.bytes_to_copy),
              Optional(params.expected_bytes_written));
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(kOutputPath, &file_contents));
  EXPECT_EQ(file_contents, params.expected_output);
}

TEST_F(CrashCollectorTest, CopyFirstNBytesFailsOnExistingFile) {
  base::test::TaskEnvironment task_env;
  const FilePath kOutputPath = test_dir_.Append("output.txt");
  const std::string kOriginalFileContents = "Haha, already a file here!";
  ASSERT_TRUE(base::WriteFile(kOutputPath, kOriginalFileContents));
  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0) << strerror(errno);
  base::ScopedFD read_fd(pipefd[0]);
  base::ScopedFD write_fd(pipefd[1]);
  const std::string kOverwriteString = "Overwrite the file!";
  base::ThreadPool::PostTask(
      FROM_HERE, base::BindLambdaForTesting([kOverwriteString,
                                             write_fd = std::move(write_fd)]() {
        base::WriteFileDescriptor(write_fd.get(), kOverwriteString);
      }));

  EXPECT_THAT(collector_.CopyFirstNBytesOfFdToNewFile(
                  read_fd.get(), kOutputPath, kOverwriteString.size() * 2),
              Eq(std::nullopt));

  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(kOutputPath, &file_contents));
  EXPECT_EQ(file_contents, kOriginalFileContents);
}

TEST_F(CrashCollectorTest, RemoveNewFileRemovesNormalFiles) {
  const FilePath kPath = test_dir_.Append("buffer.txt");
  const char kBuffer[] = "Hello, this is buffer";
  EXPECT_EQ(strlen(kBuffer), collector_.WriteNewFile(kPath, kBuffer));
  EXPECT_EQ(collector_.get_bytes_written(), strlen(kBuffer));
  EXPECT_TRUE(base::PathExists(kPath));

  EXPECT_TRUE(collector_.RemoveNewFile(kPath));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
  EXPECT_FALSE(base::PathExists(kPath));
}

TEST_F(CrashCollectorTest, RemoveNewFileRemovesCompressedFiles) {
  const FilePath kPath = test_dir_.Append("buffer.txt.gz");
  const char kBuffer[] = "Hello, this is buffer";
  EXPECT_TRUE(
      collector_.WriteNewCompressedFile(kPath, kBuffer, strlen(kBuffer)));
  EXPECT_GT(collector_.get_bytes_written(), 0);
  EXPECT_TRUE(base::PathExists(kPath));

  EXPECT_TRUE(collector_.RemoveNewFile(kPath));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
  EXPECT_FALSE(base::PathExists(kPath));
}

TEST_F(CrashCollectorTest, RemoveNewFileFailsOnNonExistantFiles) {
  const FilePath kPath = test_dir_.Append("doesnt_exist");
  EXPECT_FALSE(collector_.RemoveNewFile(kPath));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           RemoveNewFileRemovesNormalFilesInCrashLoopMode)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath = test_dir_.Append("buffer.txt");
  const char kBuffer[] = "Hello, this is buffer";
  EXPECT_EQ(strlen(kBuffer), collector.WriteNewFile(kPath, kBuffer));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer));

  EXPECT_TRUE(collector.RemoveNewFile(kPath));
  EXPECT_EQ(collector.get_bytes_written(), 0);
  EXPECT_THAT(collector.get_in_memory_files_for_test(), IsEmpty());
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           RemoveNewFileRemovesCorrectFileInCrashLoopMode)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath1 = test_dir_.Append("buffer1.txt");
  const char kBuffer1[] = "Hello, this is buffer";
  EXPECT_EQ(strlen(kBuffer1), collector.WriteNewFile(kPath1, kBuffer1));
  const FilePath kPath2 = test_dir_.Append("buffer2.txt");
  const char kBuffer2[] =
      "And if you gaze long into an abyss, you may become the domain expert on "
      "the abyss";
  EXPECT_EQ(strlen(kBuffer2), collector.WriteNewFile(kPath2, kBuffer2));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer1) + strlen(kBuffer2));

  EXPECT_TRUE(collector.RemoveNewFile(kPath1));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer2));
  auto results = collector.get_in_memory_files_for_test();
  ASSERT_EQ(results.size(), 1);
  EXPECT_EQ(std::get<0>(results[0]), "buffer2.txt");
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           RemoveNewFileRemovesCompressedFilesInCrashLoopMode)) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath = test_dir_.Append("buffer.txt.gz");
  const char kBuffer[] = "Hello, this is buffer";
  EXPECT_TRUE(
      collector.WriteNewCompressedFile(kPath, kBuffer, strlen(kBuffer)));
  EXPECT_GT(collector.get_bytes_written(), 0);

  EXPECT_TRUE(collector.RemoveNewFile(kPath));
  EXPECT_EQ(collector.get_bytes_written(), 0);
  EXPECT_THAT(collector.get_in_memory_files_for_test(), IsEmpty());
}

TEST_F(CrashCollectorTest,
       RemoveNewFileFailsOnNonExistantFilesInCrashLoopMode) {
  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  collector.Initialize(false);

  const FilePath kPath = test_dir_.Append("doesnt_exist");
  EXPECT_FALSE(collector.RemoveNewFile(kPath));
  EXPECT_EQ(collector.get_bytes_written(), 0);
}

TEST_F(CrashCollectorTest, Sanitize) {
  EXPECT_EQ("chrome", collector_.Sanitize("chrome"));
  EXPECT_EQ("CHROME", collector_.Sanitize("CHROME"));
  EXPECT_EQ("1chrome2", collector_.Sanitize("1chrome2"));
  EXPECT_EQ("chrome__deleted_", collector_.Sanitize("chrome (deleted)"));
  EXPECT_EQ("foo_bar", collector_.Sanitize("foo.bar"));
  EXPECT_EQ("", collector_.Sanitize(""));
  EXPECT_EQ("_", collector_.Sanitize(" "));
}

TEST_F(CrashCollectorTest, StripMacAddressesBasic) {
  // Basic tests of StripSensitiveData...

  // Make sure we work OK with a string w/ no MAC addresses.
  const std::string kCrashWithNoMacsOrig =
      "<7>[111566.131728] PM: Entering mem sleep\n";
  std::string crash_with_no_macs(kCrashWithNoMacsOrig);
  collector_.StripSensitiveData(&crash_with_no_macs);
  EXPECT_EQ(kCrashWithNoMacsOrig, crash_with_no_macs);

  // Make sure that we handle the case where there's nothing before/after the
  // MAC address.
  const std::string kJustAMacOrig = "11:22:33:44:55:66";
  const std::string kJustAMacStripped = "(MAC OUI=11:22:33 IFACE=1)";
  std::string just_a_mac(kJustAMacOrig);
  collector_.StripSensitiveData(&just_a_mac);
  EXPECT_EQ(kJustAMacStripped, just_a_mac);

  // Test MAC addresses crammed together to make sure it gets both of them.
  //
  // I'm not sure that the code does ideal on these two test cases (they don't
  // look like two MAC addresses to me), but since we don't see them I think
  // it's OK to behave as shown here.
  const std::string kCrammedMacs1Orig = "11:22:33:44:55:66:11:22:33:44:55:66";
  const std::string kCrammedMacs1Stripped =
      "(MAC OUI=11:22:33 IFACE=1):(MAC OUI=11:22:33 IFACE=1)";
  std::string crammed_macs_1(kCrammedMacs1Orig);
  collector_.StripSensitiveData(&crammed_macs_1);
  EXPECT_EQ(kCrammedMacs1Stripped, crammed_macs_1);

  const std::string kCrammedMacs2Orig = "11:22:33:44:55:6611:22:33:44:55:66";
  const std::string kCrammedMacs2Stripped =
      "(MAC OUI=11:22:33 IFACE=1)(MAC OUI=11:22:33 IFACE=1)";
  std::string crammed_macs_2(kCrammedMacs2Orig);
  collector_.StripSensitiveData(&crammed_macs_2);
  EXPECT_EQ(kCrammedMacs2Stripped, crammed_macs_2);

  // Test case-sensitiveness (we shouldn't be case-senstive).
  const std::string kCapsMacOrig = "AA:BB:CC:DD:EE:FF";
  const std::string kCapsMacStripped = "(MAC OUI=aa:bb:cc IFACE=1)";
  std::string caps_mac(kCapsMacOrig);
  collector_.StripSensitiveData(&caps_mac);
  EXPECT_EQ(kCapsMacStripped, caps_mac);

  const std::string kLowerMacOrig = "aa:bb:cc:dd:ee:ff";
  const std::string kLowerMacStripped = "(MAC OUI=aa:bb:cc IFACE=1)";
  std::string lower_mac(kLowerMacOrig);
  collector_.StripSensitiveData(&lower_mac);
  EXPECT_EQ(kLowerMacStripped, lower_mac);
}

TEST_F(CrashCollectorTest, StripMacAddressesBulk) {
  // Test calling StripSensitiveData w/ lots of MAC addresses in the "log".

  // Test that stripping code handles more than 256 unique MAC addresses, since
  // that overflows past the last byte...
  // We'll write up some code that generates 258 unique MAC addresses.  Sorta
  // cheating since the code is very similar to the current code in
  // StripSensitiveData(), but would catch if someone changed that later.
  std::string lotsa_macs_orig;
  std::string lotsa_macs_stripped;
  int i;
  for (i = 0; i < 258; i++) {
    lotsa_macs_orig +=
        StringPrintf(" 11:11:11:11:%02X:%02x", (i & 0xff00) >> 8, i & 0x00ff);
    lotsa_macs_stripped += StringPrintf(" (MAC OUI=11:11:11 IFACE=%d)", i + 1);
  }
  std::string lotsa_macs(lotsa_macs_orig);
  collector_.StripSensitiveData(&lotsa_macs);
  EXPECT_EQ(lotsa_macs_stripped, lotsa_macs);
}

TEST_F(CrashCollectorTest, StripSensitiveDataSample) {
  // Test calling StripSensitiveData w/ some actual lines from a real crash;
  // included two MAC addresses (though replaced them with some bogusness).
  const std::string kCrashWithMacsOrig =
      "<6>[111567.195339] ata1.00: ACPI cmd ef/10:03:00:00:00:a0 (SET FEATURES)"
      " filtered out\n"
      "<7>[108539.540144] wlan0: authenticate with 11:22:33:44:55:66 (try 1)\n"
      "<7>[108539.554973] wlan0: associate with 11:22:33:44:55:66 (try 1)\n"
      "<6>[110136.587583] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
      " QCUSBNet Ethernet Device, 99:88:77:66:55:44\n"
      "<7>[110964.314648] wlan0: deauthenticated from 11:22:33:44:55:66"
      " (Reason: 6)\n"
      "<7>[110964.325057] phy0: Removed STA 11:22:33:44:55:66\n"
      "<7>[110964.325115] phy0: Destroyed STA 11:22:33:44:55:66\n"
      "<6>[110969.219172] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
      " QCUSBNet Ethernet Device, 99:88:77:66:55:44\n"
      "<7>[111566.131728] PM: Entering mem sleep\n";
  const std::string kCrashWithMacsStripped =
      "<6>[111567.195339] ata1.00: ACPI cmd ef/(MAC OUI=10:03:00 IFACE=1) (SET "
      "FEATURES)"
      " filtered out\n"
      "<7>[108539.540144] wlan0: authenticate with (MAC OUI=11:22:33 IFACE=2) "
      "(try 1)\n"
      "<7>[108539.554973] wlan0: associate with (MAC OUI=11:22:33 IFACE=2) "
      "(try 1)\n"
      "<6>[110136.587583] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
      " QCUSBNet Ethernet Device, (MAC OUI=99:88:77 IFACE=3)\n"
      "<7>[110964.314648] wlan0: deauthenticated from (MAC OUI=11:22:33 "
      "IFACE=2)"
      " (Reason: 6)\n"
      "<7>[110964.325057] phy0: Removed STA (MAC OUI=11:22:33 IFACE=2)\n"
      "<7>[110964.325115] phy0: Destroyed STA (MAC OUI=11:22:33 IFACE=2)\n"
      "<6>[110969.219172] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
      " QCUSBNet Ethernet Device, (MAC OUI=99:88:77 IFACE=3)\n"
      "<7>[111566.131728] PM: Entering mem sleep\n";
  std::string crash_with_macs(kCrashWithMacsOrig);
  collector_.StripSensitiveData(&crash_with_macs);
  EXPECT_EQ(kCrashWithMacsStripped, crash_with_macs);
}

TEST_F(CrashCollectorTest, StripEmailAddresses) {
  std::string logs =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
      " sed do eiusmod tempor incididunt ut labore et dolore \n"
      "magna aliqua. Ut enim ad minim veniam, quis nostrud "
      "exercitation ullamco foo.bar+baz@secret.com laboris \n"
      "nisi ut aliquip ex ea commodo consequat. Duis aute "
      "irure dolor in reprehenderit (support@example.com) in \n"
      "voluptate velit esse cillum dolore eu fugiat nulla "
      "pariatur. Excepteur sint occaecat:abuse@dev.reallylong,\n"
      "cupidatat non proident, sunt in culpa qui officia "
      "deserunt mollit anim id est laborum.";
  collector_.StripSensitiveData(&logs);
  EXPECT_EQ(0, logs.find("Lorem ipsum"));
  EXPECT_EQ(std::string::npos, logs.find("foo.bar"));
  EXPECT_EQ(std::string::npos, logs.find("secret"));
  EXPECT_EQ(std::string::npos, logs.find("support"));
  EXPECT_EQ(std::string::npos, logs.find("example.com"));
  EXPECT_EQ(std::string::npos, logs.find("abuse"));
  EXPECT_EQ(std::string::npos, logs.find("dev.reallylong"));
}

TEST_F(CrashCollectorTest, StripGaiaId) {
  std::string kCrashWithGaiaID =
      "remove gaia_id:\"970787480432\" sample"
      "don't remove 970787480432 sample"
      "remove {id: 123, email: test1234} sample"
      "don't remove id: 1234 sample"
      "don't remove email_id: 1234";
  std::string kCrashWithoutGaiaID =
      "remove gaia_id:\"(GAIA: 1)\" sample"
      "don't remove 970787480432 sample"
      "remove {id: (GAIA: 2), email: test1234} sample"
      "don't remove id: 1234 sample"
      "don't remove email_id: 1234";
  collector_.StripSensitiveData(&kCrashWithGaiaID);
  EXPECT_EQ(kCrashWithGaiaID, kCrashWithoutGaiaID);
}

TEST_F(CrashCollectorTest, StripLocationInformation) {
  std::string kCrashWithLocationInformation =
      "remove Cell ID: 'AB123' sample"
      "stay Cell: '123' sample"
      "remove Location area code: '12Abcd3' sample"
      "stay Location area code: '123AsDF' sample"
      "stay code: 33 sample"
      "remove Cell ID: '234234' sample";

  std::string kCrashWithoutLocationInformation =
      "remove Cell ID: '(CellID: 1)' sample"
      "stay Cell: '123' sample"
      "remove Location area code: '(LocAC: 1)' sample"
      "stay Location area code: '123AsDF' sample"
      "stay code: 33 sample"
      "remove Cell ID: '(CellID: 2)' sample";
  collector_.StripSensitiveData(&kCrashWithLocationInformation);
  EXPECT_EQ(kCrashWithLocationInformation, kCrashWithoutLocationInformation);
}

TEST_F(CrashCollectorTest, StripIPv4Addresses) {
  std::string logs =
      "stay.1.2.3 remove.1.2.3.4."
      "stay 255.255 255.255.255 255.255.259.255 255.255.255.255 remove 0.0.0.0 "
      "stay 19.259.243.255 19.243.343.255 remove 19.143.29.255";
  std::string redacted_log =
      "stay.1.2.3 remove.(IPv4: 1)."
      "stay 255.255 255.255.255 255.255.259.255 255.255.255.255 remove "
      "(0.0.0.0/8: 2) "
      "stay 19.259.243.255 19.243.343.255 remove (IPv4: 3)";
  collector_.StripSensitiveData(&logs);
  EXPECT_EQ(logs, redacted_log);
}

TEST_F(CrashCollectorTest, StripIPv6Addresses) {
  // TODO(donnadionne): address (1::) is not currently redacted
  // because (::) is skipped as the unspecified address.
  std::string logs =
      "stay:2001:0db8:0000:0000:0000:ff00:0042: "
      "stay:0:0:0:0:0:FFFF:322.1.41.90 "
      "remove:2001:0db8:0000:0000:0000:ff00:0042:8329 "
      "remove:2001:0dB8:0000:0000:0000:Ff00:0042:8329 "
      "remove:2001:db8:0:0:0:ff00:42:8329 2001:db8::ff00:42:8329 ::1 1:: "
      "remove:0:0:0:0:0:FFFF:222.1.41.90";
  std::string redacted_log =
      "stay:2001:0db8:0000:0000:0000:ff00:0042: "
      "stay:0:0:0:0:0:FFFF:3(IPv4: 1) "
      "remove:(IPv6: 1) "
      "remove:(IPv6: 2) "
      "remove:(IPv6: 3) (IPv6: 4) ::1 1:: "
      "remove:0:0:0:0:0:FFFF:(IPv4: 2)";
  collector_.StripSensitiveData(&logs);
  EXPECT_EQ(logs, redacted_log);
}

TEST_F(CrashCollectorTest, StripSerialNumbers) {
  // Test calling StripSensitiveData w/ some actual lines from a real crash;
  // included two serial numbers (though replaced them with some bogusness).
  const std::string kCrashWithUsbSerialNumbers =
      "[ 1.974401] usb 1-7: new high-speed USB device number 4 using xhci_hcd\n"
      "[ 2.159587] usb 1-7: New USB device found, idVendor=2232, "
      "idProduct=1082, bcdDevice= 0.08\n"
      "[ 2.159620] usb 1-7: New USB device strings: Mfr=3, Product=1, "
      "SerialNumber=2\n"
      "[ 2.159644] usb 1-7: Product: 720p HD Camera\n"
      "[ 2.159661] usb 1-7: Manufacturer: Namuga\n"
      "[ 2.159676] usb 1-7: SerialNumber: 200901010001\n"
      "[ 2.212541] usb 1-2.1: new high-speed USB device number 5 using "
      "xhci_hcd\n"
      "[ 2.248559] Switched to clocksource tsc\n"
      "[ 2.296473] usb 1-2.1: New USB device found, idVendor=0409, "
      "idProduct=005a, bcdDevice= 1.00\n"
      "[ 2.296506] usb 1-2.1: New USB device strings: Mfr=0, Product=0, "
      "SerialNumber=0\n"
      "[ 2.297266] hub 1-2.1:1.0: USB hub found\n"
      "[ 2.297326] hub 1-2.1:1.0: 4 ports detected\n"
      "[ 2.570494] usb 1-2.1.2: new high-speed USB device number 6 using "
      "xhci_hcd\n"
      "[ 2.670246] usb 1-2.1.2: New USB device found, idVendor=13fe, "
      "idProduct=5500, bcdDevice= 1.00\n"
      "[ 2.670286] usb 1-2.1.2: New USB device strings: Mfr=1, Product=2, "
      "SerialNumber=3\n"
      "[ 2.670338] usb 1-2.1.2: Product: Patriot Memory\n"
      "[ 2.670359] usb 1-2.1.2: Manufacturer:\n"
      "[ 2.670379] usb 1-2.1.2: SerialNumber: 0701534FB0282809\n";
  const std::string kCrashWithUsbSerialNumbersStripped =
      "[ 1.974401] usb 1-7: new high-speed USB device number 4 using xhci_hcd\n"
      "[ 2.159587] usb 1-7: New USB device found, idVendor=2232, "
      "idProduct=1082, bcdDevice= 0.08\n"
      "[ 2.159620] usb 1-7: New USB device strings: Mfr=3, Product=1, "
      "SerialNumber=(Serial: 1)\n"
      "[ 2.159644] usb 1-7: Product: 720p HD Camera\n"
      "[ 2.159661] usb 1-7: Manufacturer: Namuga\n"
      "[ 2.159676] usb 1-7: SerialNumber: (Serial: 2)\n"
      "[ 2.212541] usb 1-2.1: new high-speed USB device number 5 using "
      "xhci_hcd\n"
      "[ 2.248559] Switched to clocksource tsc\n"
      "[ 2.296473] usb 1-2.1: New USB device found, idVendor=0409, "
      "idProduct=005a, bcdDevice= 1.00\n"
      "[ 2.296506] usb 1-2.1: New USB device strings: Mfr=0, Product=0, "
      "SerialNumber=(Serial: 3)\n"
      "[ 2.297266] hub 1-2.1:1.0: USB hub found\n"
      "[ 2.297326] hub 1-2.1:1.0: 4 ports detected\n"
      "[ 2.570494] usb 1-2.1.2: new high-speed USB device number 6 using "
      "xhci_hcd\n"
      "[ 2.670246] usb 1-2.1.2: New USB device found, idVendor=13fe, "
      "idProduct=5500, bcdDevice= 1.00\n"
      "[ 2.670286] usb 1-2.1.2: New USB device strings: Mfr=1, Product=2, "
      "SerialNumber=(Serial: 4)\n"
      "[ 2.670338] usb 1-2.1.2: Product: Patriot Memory\n"
      "[ 2.670359] usb 1-2.1.2: Manufacturer:\n"
      "[ 2.670379] usb 1-2.1.2: SerialNumber: (Serial: 5)\n";
  std::string crash_with_usb_serial_numbers(kCrashWithUsbSerialNumbers);
  collector_.StripSensitiveData(&crash_with_usb_serial_numbers);
  EXPECT_EQ(kCrashWithUsbSerialNumbersStripped, crash_with_usb_serial_numbers);
}

TEST_F(CrashCollectorTest, StripRecoveryId) {
  const std::string kCrashWithRecoveryId =
      "2022-10-13T07:35:34.518810Z INFO cryptohomed[2055]: AuthSession: "
      "started with is_ephemeral_user=0 intent=decrypt user_exists=1 keys=.\n"
      "2022-10-13T07:35:34.576054Z INFO cryptohomed[2055]: "
      "GenerateRecoveryRequestAssociatedData for recovery_id: "
      "3ecb8fc835a164e741f3e002a93495ea9b2f40dcf16acb393c30c3b18768ddce\n"
      "2022-10-13T07:35:36.060608Z INFO cryptohomed[2055]: AuthSession: "
      "decrypt authentication attempt via test-recovery factor.";
  const std::string kCrashWithRecoveryIdStripped =
      "2022-10-13T07:35:34.518810Z INFO cryptohomed[2055]: AuthSession: "
      "started with is_ephemeral_user=0 intent=decrypt user_exists=1 keys=.\n"
      "2022-10-13T07:35:34.576054Z INFO cryptohomed[2055]: "
      "GenerateRecoveryRequestAssociatedData for recovery_id: (HASH:3ecb 1)\n"
      "2022-10-13T07:35:36.060608Z INFO cryptohomed[2055]: AuthSession: "
      "decrypt authentication attempt via test-recovery factor.";
  std::string crash_with_recovery_id(kCrashWithRecoveryId);
  collector_.StripSensitiveData(&crash_with_recovery_id);
  EXPECT_EQ(kCrashWithRecoveryIdStripped, crash_with_recovery_id);
}

TEST_F(CrashCollectorTest, GetCrashDirectoryInfoOld) {
  FilePath path;
  const int kRootUid = 0;
  const int kNtpUid = 5;
  const int kChronosUid = 1000;
  const int kCrashAccessGid = 419;
  const mode_t kExpectedSystemMode = 02770;

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;

  path = collector_
             .GetCrashDirectoryInfoOld(kRootUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);

  path = collector_
             .GetCrashDirectoryInfoOld(kNtpUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);

#if !USE_KVM_GUEST
  const int kCrashUserUid = 20137;
  const int kCrashUserAccessGid = 420;
  const mode_t kExpectedUserMode = 02770;
  const mode_t kExpectedDaemonStoreMode = 03770;

  // When running in the VM, all crashes will go to the system directory.
  auto* mock = new org::chromium::SessionManagerInterfaceProxyMock;
  test_util::SetActiveSessions(mock, {{"user", "hashcakes"}});
  collector_.session_manager_proxy_.reset(mock);

  path =
      collector_
          .GetCrashDirectoryInfoOld(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
  EXPECT_EQ(test_dir_.Append("home/user/hashcakes/crash").value(),
            path.value());
  EXPECT_EQ(kExpectedUserMode, directory_mode);
  EXPECT_EQ(kChronosUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);

  collector_.crash_directory_selection_method_ =
      CrashCollector::kAlwaysUseDaemonStore;
  path =
      collector_
          .GetCrashDirectoryInfoOld(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
  EXPECT_EQ(test_dir_.Append("run/daemon-store/crash/hashcakes").value(),
            path.value());
  EXPECT_EQ(kExpectedDaemonStoreMode, directory_mode);
  EXPECT_EQ(kCrashUserUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);
#endif  // !USE_KVM_GUEST
}

TEST_F(CrashCollectorTest, GetCrashDirectoryInfoOldLoggedOut) {
  FilePath path;
  const int kChronosUid = 1000;
  const mode_t kExpectedUserMode = 02770;

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;

  auto* mock = new org::chromium::SessionManagerInterfaceProxyMock;
  test_util::SetActiveSessions(mock, {});
  collector_.session_manager_proxy_.reset(mock);

  path =
      collector_
          .GetCrashDirectoryInfoOld(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
  EXPECT_EQ(kExpectedUserMode, directory_mode);
#if USE_KVM_GUEST
  // Inside the VM, everything goes to /var/spool/crash.
  const int kCrashAccessGid = 419;
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(0, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);
#else
  const int kCrashUserAccessGid = 420;
  EXPECT_EQ("/home/chronos/crash", path.value());
  EXPECT_EQ(kChronosUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);
#endif  // USE_KVM_GUEST
}

TEST_F(CrashCollectorTest, GetCrashDirectoryInfoNew) {
  FilePath path;
  const int kRootUid = 0;
  const int kNtpUid = 5;
  const int kChronosUid = 1000;

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;

  // all crashes will first look at daemon store
  auto* mock = new org::chromium::SessionManagerInterfaceProxyMock;
  test_util::SetActiveSessions(mock, {{"user", "hashcakes"}});
  collector_.session_manager_proxy_.reset(mock);

#if USE_KVM_GUEST
  const int kCrashAccessGid = 419;
  const mode_t kExpectedSystemMode = 02770;
  // In the guest, we use /var/spool/crash even though we're logged in
  path = collector_
             .GetCrashDirectoryInfoNew(kRootUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);

  path = collector_
             .GetCrashDirectoryInfoNew(kNtpUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);
#else   // USE_KVM_GUEST
  const int kCrashUserUid = 20137;
  const int kCrashUserAccessGid = 420;
  const mode_t kExpectedDaemonStoreMode = 03770;
  const FilePath kExpectedDir = paths::Get("/run/daemon-store/crash/hashcakes");

  // Create crash-test-in-progress file to force deterministic
  // (always-daemon-store) behavior, rather than randomizing.
  FilePath test_in_prog = paths::GetAt(paths::kSystemRunStateDirectory,
                                       paths::kCrashTestInProgress);
  ASSERT_TRUE(test_util::CreateFile(test_in_prog, ""));

  // In the host, we always use daemon_store when logged in.
  path = collector_
             .GetCrashDirectoryInfoNew(kRootUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ(kExpectedDir, path);
  EXPECT_EQ(kExpectedDaemonStoreMode, directory_mode);
  EXPECT_EQ(kCrashUserUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);

  path = collector_
             .GetCrashDirectoryInfoNew(kNtpUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ(kExpectedDir, path);
  EXPECT_EQ(kExpectedDaemonStoreMode, directory_mode);
  EXPECT_EQ(kCrashUserUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);

  path =
      collector_
          .GetCrashDirectoryInfoNew(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
  EXPECT_EQ(kExpectedDir, path);
  EXPECT_EQ(kExpectedDaemonStoreMode, directory_mode);
  EXPECT_EQ(kCrashUserUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);

  collector_.crash_directory_selection_method_ =
      CrashCollector::kAlwaysUseDaemonStore;
  path =
      collector_
          .GetCrashDirectoryInfoNew(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
  EXPECT_EQ(kExpectedDir, path);
  EXPECT_EQ(kExpectedDaemonStoreMode, directory_mode);
  EXPECT_EQ(kCrashUserUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);
#endif  // USE_KVM_GUEST
}

TEST_F(CrashCollectorTest, GetCrashDirectoryInfoNewLoggedOut) {
  FilePath path;
  const int kRootUid = 0;
  const int kNtpUid = 5;
  const int kCrashAccessGid = 419;
  const int kChronosUid = 1000;
  const mode_t kExpectedSystemMode = 02770;

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;

  auto* mock = new org::chromium::SessionManagerInterfaceProxyMock;
  test_util::SetActiveSessions(mock, {});
  collector_.session_manager_proxy_.reset(mock);

  // When not logged in, system dirs should use /var/spool/crash/ (in VM or not)
  path = collector_
             .GetCrashDirectoryInfoNew(kRootUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);

  path = collector_
             .GetCrashDirectoryInfoNew(kNtpUid, kChronosUid, &directory_mode,
                                       &directory_owner, &directory_group)
             .value();
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
  EXPECT_EQ(kRootUid, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);

  path =
      collector_
          .GetCrashDirectoryInfoNew(kChronosUid, kChronosUid, &directory_mode,
                                    &directory_owner, &directory_group)
          .value();
#if USE_KVM_GUEST
  // Inside the VM, everything goes to /var/spool/crash.
  EXPECT_EQ("/var/spool/crash", path.value());
  EXPECT_EQ(0, directory_owner);
  EXPECT_EQ(kCrashAccessGid, directory_group);
  EXPECT_EQ(kExpectedSystemMode, directory_mode);
#else
  const int kCrashUserAccessGid = 420;
  EXPECT_EQ(paths::Get("/home/chronos/crash"), path);
  EXPECT_EQ(kChronosUid, directory_owner);
  EXPECT_EQ(kCrashUserAccessGid, directory_group);
  EXPECT_EQ(kExpectedSystemMode, directory_mode);

  collector_.crash_directory_selection_method_ =
      CrashCollector::kAlwaysUseDaemonStore;
  std::optional<FilePath> path_maybe = collector_.GetCrashDirectoryInfoNew(
      kChronosUid, kChronosUid, &directory_mode, &directory_owner,
      &directory_group);
  EXPECT_FALSE(path_maybe.has_value());
#endif  // USE_KVM_GUEST
}

TEST_F(CrashCollectorTest, FormatDumpBasename) {
  struct tm tm = {};
  tm.tm_sec = 15;
  tm.tm_min = 50;
  tm.tm_hour = 13;
  tm.tm_mday = 23;
  tm.tm_mon = 4;
  tm.tm_year = 110;
  tm.tm_isdst = -1;
  std::string basename = collector_.FormatDumpBasename("foo", timegm(&tm), 100);
  EXPECT_THAT(basename,
              testing::MatchesRegex(R"(foo\.20100523\.135015\.[0-9]{5}\.100)"));
}

TEST_F(CrashCollectorTest, GetCrashPath) {
  EXPECT_EQ("/var/spool/crash/myprog.20100101.1200.56789.1234.core",
            collector_
                .GetCrashPath(FilePath("/var/spool/crash"),
                              "myprog.20100101.1200.56789.1234", "core")
                .value());
  EXPECT_EQ("/home/chronos/user/crash/chrome.20100101.1200.56789.1234.dmp",
            collector_
                .GetCrashPath(FilePath("/home/chronos/user/crash"),
                              "chrome.20100101.1200.56789.1234", "dmp")
                .value());
}

TEST_F(CrashCollectorTest, ParseProcessTicksFromStat) {
  uint64_t ticks;
  EXPECT_FALSE(CrashCollector::ParseProcessTicksFromStat("", &ticks));
  EXPECT_FALSE(CrashCollector::ParseProcessTicksFromStat("123 (foo)", &ticks));

  constexpr char kTruncatedStat[] =
      "234641 (cat) R 234581 234641 234581 34821 234641 4194304 117 0 0 0 0 0 "
      "0 0 20 0 1 0";

  EXPECT_FALSE(
      CrashCollector::ParseProcessTicksFromStat(kTruncatedStat, &ticks));

  constexpr char kInvalidStat[] =
      "234641 (cat) R 234581 234641 234581 34821 234641 4194304 117 0 0 0 0 0 "
      "0 0 20 0 1 0 foo";

  EXPECT_FALSE(CrashCollector::ParseProcessTicksFromStat(kInvalidStat, &ticks));

  // Executable name is ") (".
  constexpr char kStat[] =
      "234641 () () R 234581 234641 234581 34821 234641 4194304 117 0 0 0 0 0 "
      "0 0 20 0 1 0 2092891 6090752 182 18446744073709551615 94720364494848 "
      "94720364525584 140735323062016 0 0 0 0 0 0 0 0 0 17 32 0 0 0 0 0 "
      "94720366623824 94720366625440 94720371765248 140735323070153 "
      "140735323070173 140735323070173 140735323074543 0";

  EXPECT_TRUE(CrashCollector::ParseProcessTicksFromStat(kStat, &ticks));
  EXPECT_EQ(2092891, ticks);
}

TEST_F(CrashCollectorTest, GetUptime) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());

  base::TimeDelta uptime_at_process_start;
  EXPECT_TRUE(CrashCollector::GetUptimeAtProcessStart(
      getpid(), &uptime_at_process_start));

  base::TimeDelta uptime;
  EXPECT_TRUE(collector_.GetUptime(&uptime));

#if defined(ARCH_CPU_ARM_FAMILY)
  // On QEMU simulator (used for ARM testing), stat always says the uptime at
  // process start is zero. (This was fixed in Jan 2022, but we don't have the
  // patch yet.) Just test we didn't get a negative value. (Once we get the
  // patch, the test will still pass, to avoid blocking uprev.)
  EXPECT_FALSE(uptime_at_process_start.is_negative())
      << uptime_at_process_start;
#else
  // On non-QEMU, the machine should have been up for a little while before
  // the process started.
  EXPECT_TRUE(uptime_at_process_start.is_positive()) << uptime_at_process_start;
#endif
  EXPECT_TRUE(uptime.is_positive()) << uptime;
  EXPECT_GT(uptime, uptime_at_process_start);
}

bool CrashCollectorTest::CheckHasCapacity() {
  std::string full_message = StringPrintf("Crash directory %s already full",
                                          test_dir_.value().c_str());
  bool has_capacity = collector_.CheckHasCapacity(test_dir_);
  bool has_message = FindLog(full_message.c_str());
  EXPECT_EQ(has_message, !has_capacity);
  return has_capacity;
}

TEST_F(CrashCollectorTest, CheckHasCapacityUsual) {
  // Test kMaxCrashDirectorySize - 1 non-meta files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf("file%d.core", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test supplemental files fit with longer names.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf("file%d.log.gz", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize - 1 meta files fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf("file%d.meta", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }

  // Test an additional kMaxCrashDirectorySize meta files don't fit.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf("overage%d.meta", i)), ""));
    EXPECT_FALSE(CheckHasCapacity());
  }
}

TEST_F(CrashCollectorTest, CheckHasCapacityCorrectBasename) {
  // Test kMaxCrashDirectorySize - 1 files can be added.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 1; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf("file.%d.core", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }
  ASSERT_TRUE(test_util::CreateFile(test_dir_.Append("file.last.core"), ""));
  EXPECT_FALSE(CheckHasCapacity());
}

TEST_F(CrashCollectorTest, CheckHasCapacityStrangeNames) {
  // Test many files with different extensions and same base fit.
  for (int i = 0; i < 5 * CrashCollector::kMaxCrashDirectorySize; ++i) {
    ASSERT_TRUE(
        test_util::CreateFile(test_dir_.Append(StringPrintf("a.%d", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }
  // Test dot files are treated as individual files.
  for (int i = 0; i < CrashCollector::kMaxCrashDirectorySize - 2; ++i) {
    ASSERT_TRUE(test_util::CreateFile(
        test_dir_.Append(StringPrintf(".file%d", i)), ""));
    EXPECT_TRUE(CheckHasCapacity());
  }
  ASSERT_TRUE(test_util::CreateFile(test_dir_.Append("normal.meta"), ""));
  EXPECT_TRUE(CheckHasCapacity());
}

struct MetaDataTest {
  std::string test_case_name;
  bool test_in_prog = false;
  bool add_variations = false;
  bool use_saved_lsb = false;
  std::string exec_name = "kernel";
  std::optional<bool> enterprise_enrolled = false;
  std::string expected_meta;
};

class CrashCollectorParameterizedTest
    : public CrashCollectorTest,
      public ::testing::WithParamInterface<MetaDataTest> {
 public:
  static constexpr char kPayloadName[] = "payload-file";
  static constexpr char kKernelName[] = "Linux";
  static constexpr char kKernelVersion[] =
      "3.8.11 #1 SMP Wed Aug 22 02:18:30 PDT 2018";
  static constexpr int kNumExperiments = 17;
  static constexpr char kVariations[] =
      "3ac60855-486e2a9c,63dcb6a3-f774aad2,"
      "e706e746-e4cdf2fd,f296190c-4c073154,4442aae2-4ad60575,f690cf64-75cb33fc,"
      "ed1d377-e1cc0f14,75f0f0a0-e1cc0f14,e2b18481-7158671e,e7e71889-e1cc0f14,"
      "31f573d2-ca7d8d80,c559031-3d47f4f4,9a38bae3-3d47f4f4,6f3a6be-3d47f4f4,"
      "e43d4487-3d47f4f4,c1405ec8-fb0c8ff1,dab0c6bc-3f4a17df,";
  static constexpr char kVariationsFile[] =
      "num-experiments=17\n"
      "variations=3ac60855-486e2a9c,63dcb6a3-f774aad2,"
      "e706e746-e4cdf2fd,f296190c-4c073154,4442aae2-4ad60575,f690cf64-75cb33fc,"
      "ed1d377-e1cc0f14,75f0f0a0-e1cc0f14,e2b18481-7158671e,e7e71889-e1cc0f14,"
      "31f573d2-ca7d8d80,c559031-3d47f4f4,9a38bae3-3d47f4f4,6f3a6be-3d47f4f4,"
      "e43d4487-3d47f4f4,c1405ec8-fb0c8ff1,dab0c6bc-3f4a17df,\n";
  // Returns the time we want to use for the OS timestamp. Returns the
  // same value (May 3, 2020 -- basically arbitrary) every time it is run, but
  // base::Time doesn't support constexpr.
  static base::Time GetOsTimeForTest() {
    base::Time::Exploded exploded;
    exploded.year = 2020;
    exploded.month = 5;
    exploded.day_of_month = 3;
    exploded.day_of_week = 0;
    exploded.hour = 7;
    exploded.minute = 22;
    exploded.second = 41;
    // Must not have a millisecond component because ext2/ext3 have a second
    // granularity.
    exploded.millisecond = 0;
    base::Time result;
    CHECK(base::Time::FromUTCExploded(exploded, &result));
    return result;
  }
};

constexpr char CrashCollectorParameterizedTest::kPayloadName[];
constexpr char CrashCollectorParameterizedTest::kKernelName[];
constexpr char CrashCollectorParameterizedTest::kKernelVersion[];

TEST_P(CrashCollectorParameterizedTest, MetaData) {
  MetaDataTest test_case = GetParam();
  if (test_case.test_in_prog) {
    ASSERT_TRUE(
        test_util::CreateFile(paths::GetAt(paths::kSystemRunStateDirectory,
                                           paths::kInProgressTestName),
                              "some.Test"));
  }

  if (test_case.add_variations) {
    ASSERT_TRUE(test_util::CreateFile(
        paths::GetAt(paths::kFallbackToHomeDir, paths::kVariationsListFile),
        kVariationsFile));
  }

  const char kMetaFileBasename[] = "generated.meta";
  FilePath meta_file = test_dir_.Append(kMetaFileBasename);

  FilePath lsb_release = paths::Get("/etc/lsb-release");
  collector_.set_lsb_release_for_test(lsb_release);
  const char kLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=82\n"
      "CHROMEOS_RELEASE_TRACK=testimage-channel\n"
      "CHROMEOS_RELEASE_DESCRIPTION=6727.0.2015_01_26_0853 (Test Build - foo)";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kLsbContents));
  const base::Time kFakeOsTime = GetOsTimeForTest();
  ASSERT_TRUE(base::TouchFile(lsb_release, kFakeOsTime, kFakeOsTime));

  FilePath saved_lsb_dir = paths::Get(paths::kCrashReporterStateDirectory);
  collector_.set_reporter_state_directory_for_test(saved_lsb_dir);

  const char kSavedLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=12345.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=81\n"
      "CHROMEOS_RELEASE_TRACK=beta-channel\n"
      "CHROMEOS_RELEASE_DESCRIPTION=12345.0.2015_01_26_0853 (Test Build - foo)";
  base::FilePath saved_lsb = saved_lsb_dir.Append("lsb-release");
  ASSERT_TRUE(test_util::CreateFile(saved_lsb, kSavedLsbContents));
  ASSERT_TRUE(base::TouchFile(saved_lsb, kFakeOsTime, kFakeOsTime));

  const char kPayload[] = "foo";
  FilePath payload_file = test_dir_.Append(kPayloadName);
  ASSERT_TRUE(test_util::CreateFile(payload_file, kPayload));

  collector_.AddCrashMetaData("foo", "bar");
  collector_.AddCrashMetaData("weird  key#@!", "weird\nvalue");

  // Empty key should be ignored and not added.
  collector_.AddCrashMetaData("", "empty_key_val");

  std::unique_ptr<base::SimpleTestClock> test_clock =
      std::make_unique<base::SimpleTestClock>();
  test_clock->SetNow(base::Time::UnixEpoch() + base::Milliseconds(kFakeNow));
  collector_.set_test_clock(std::move(test_clock));
  collector_.set_test_kernel_info(kKernelName, kKernelVersion);
  std::unique_ptr<policy::MockDevicePolicy> test_device_policy =
      std::make_unique<policy::MockDevicePolicy>();
  if (!test_case.enterprise_enrolled) {
    EXPECT_CALL(*test_device_policy, LoadPolicy(/*delete_invalid_files=*/false))
        .WillOnce(Return(false));
  } else {
    EXPECT_CALL(*test_device_policy, LoadPolicy(/*delete_invalid_files=*/false))
        .WillOnce(Return(true));
    EXPECT_CALL(*test_device_policy, IsEnterpriseEnrolled())
        .WillOnce(Return(*test_case.enterprise_enrolled));
  }
  collector_.set_device_policy_for_test(std::move(test_device_policy));

  collector_.SetUseSavedLsb(test_case.use_saved_lsb);
  collector_.FinishCrash(meta_file, test_case.exec_name, kPayloadName);

  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(meta_file, &contents));
  EXPECT_EQ(test_case.expected_meta, contents);
  EXPECT_EQ(test_case.expected_meta.size(), collector_.get_bytes_written());
}

std::vector<MetaDataTest> GenerateMetaDataTests() {
  const base::Time kOsTimestamp =
      CrashCollectorParameterizedTest::GetOsTimeForTest();
  MetaDataTest base;
  base.test_case_name = "Base";
  base.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=test\n"
      "upload_var_is-enterprise-enrolled=false\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest base_saved_lsb;
  base_saved_lsb.use_saved_lsb = true;
  base_saved_lsb.test_case_name = "BaseUseSavedLsb";
  base_saved_lsb.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=beta\n"
      "upload_var_is-enterprise-enrolled=false\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=12345.0.2015_01_26_0853\n"
      "upload_var_lsb-release=12345.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=81\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest test_in_progress;
  test_in_progress.test_case_name = "Test_in_progress";
  test_in_progress.test_in_prog = true;
  test_in_progress.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=test\n"
      "upload_var_is-enterprise-enrolled=false\n"
      "upload_var_in_progress_integration_test=some.Test\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest variations;
  variations.test_case_name = "Variations";
  variations.add_variations = true;
  variations.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_variations=%s\n"
      "upload_var_num-experiments=%d\n"
      "upload_var_channel=test\n"
      "upload_var_is-enterprise-enrolled=false\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      CrashCollectorParameterizedTest::kVariations,
      CrashCollectorParameterizedTest::kNumExperiments, kFakeNow,
      (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest no_exec_name;
  no_exec_name.test_case_name = "No_exec_name";
  no_exec_name.exec_name = "";
  no_exec_name.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=test\n"
      "upload_var_is-enterprise-enrolled=false\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest enterprise_enrolled;
  enterprise_enrolled.test_case_name = "Enterprise_enrolled";
  enterprise_enrolled.enterprise_enrolled = true;
  enterprise_enrolled.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=test\n"
      "upload_var_is-enterprise-enrolled=true\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  MetaDataTest device_policy_not_loaded;
  device_policy_not_loaded.test_case_name = "Device_policy_not_loaded";
  device_policy_not_loaded.enterprise_enrolled = std::nullopt;
  device_policy_not_loaded.expected_meta = StringPrintf(
      "upload_var_collector=mock\n"
      "foo=bar\n"
      "weird__key___=weird\\nvalue\n"
      "upload_var_channel=test\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=kernel\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      kFakeNow, (kOsTimestamp - base::Time::UnixEpoch()).InMilliseconds(),
      CrashCollectorParameterizedTest::kKernelName,
      CrashCollectorParameterizedTest::kKernelVersion,
      CrashCollectorParameterizedTest::kPayloadName);

  return {
      base,         base_saved_lsb,      test_in_progress,        variations,
      no_exec_name, enterprise_enrolled, device_policy_not_loaded};
}

INSTANTIATE_TEST_SUITE_P(CrashCollectorInstantiation,
                         CrashCollectorParameterizedTest,
                         testing::ValuesIn(GenerateMetaDataTests()),
                         [](const testing::TestParamInfo<MetaDataTest>& info) {
                           return info.param.test_case_name;
                         });

TEST_F(CrashCollectorTest, ErrorCollectionMetaData) {
  // Set up metadata the collector will read
  FilePath lsb_release = paths::Get("/etc/lsb-release");
  std::string contents;
  collector_.set_lsb_release_for_test(lsb_release);
  const char kLsbContents[] =
      "CHROMEOS_RELEASE_BOARD=lumpy\n"
      "CHROMEOS_RELEASE_VERSION=6727.0.2015_01_26_0853\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_CHROME_MILESTONE=82\n"
      "CHROMEOS_RELEASE_TRACK=beta-channel\n"
      "CHROMEOS_RELEASE_DESCRIPTION=6727.0.2015_01_26_0853 (Test Build - foo)";
  ASSERT_TRUE(test_util::CreateFile(lsb_release, kLsbContents));
  base::Time os_time = base::Time::Now() - base::Days(123);
  // ext2/ext3 seem to have a timestamp granularity of 1s so round this time
  // value down to the nearest second.
  os_time = base::Seconds((os_time - base::Time::UnixEpoch()).InSeconds()) +
            base::Time::UnixEpoch();
  ASSERT_TRUE(base::TouchFile(lsb_release, os_time, os_time));

  std::unique_ptr<base::SimpleTestClock> test_clock =
      std::make_unique<base::SimpleTestClock>();
  test_clock->SetNow(base::Time::UnixEpoch() + base::Milliseconds(kFakeNow));
  collector_.set_test_clock(std::move(test_clock));

  const char kKernelName[] = "Linux";
  const char kKernelVersion[] = "3.8.11 #1 SMP Wed Aug 22 02:18:30 PDT 2018";
  collector_.set_test_kernel_info(kKernelName, kKernelVersion);
  collector_.set_crash_directory_for_test(test_dir_);

  collector_.EnqueueCollectionErrorLog(
      CrashCollector::kErrorUnsupported32BitCoreFile, "some_exec");

  base::FilePath meta_file_path;
  ASSERT_TRUE(test_util::DirectoryHasFileWithPattern(
      test_dir_, "crash_reporter_failure.*.meta", &meta_file_path));

  base::FilePath base_name = meta_file_path.BaseName().RemoveExtension();
  base::FilePath pslog_name = base_name.AddExtension("pslog");
  base::FilePath log_name = base_name.AddExtension("log");

  EXPECT_TRUE(base::ReadFileToString(meta_file_path, &contents));
  std::string expected_meta = StringPrintf(
      "upload_var_collector=crash_reporter_failure\n"
      "upload_var_orig_collector=mock\n"
      "upload_var_orig_exec=some_exec\n"
      "sig=crash_reporter-user-collection_unsupported-32bit-core-file\n"
      "error_type=unsupported-32bit-core-file\n"
      "upload_file_pslog=%s\n"
      "upload_var_channel=beta\n"
      "upload_var_reportTimeMillis=%" PRId64
      "\n"
      "exec_name=crash_reporter_failure\n"
      "ver=6727.0.2015_01_26_0853\n"
      "upload_var_lsb-release=6727.0.2015_01_26_0853 (Test Build - foo)\n"
      "upload_var_cros_milestone=82\n"
      "os_millis=%" PRId64
      "\n"
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n"
      "payload=%s\n"
      "done=1\n",
      pslog_name.value().c_str(), kFakeNow,
      (os_time - base::Time::UnixEpoch()).InMilliseconds(), kKernelName,
      kKernelVersion, log_name.value().c_str());
  EXPECT_EQ(expected_meta, contents);
}

// Test target of symlink is not overwritten.
TEST_F(CrashCollectorTest, MetaDataDoesntOverwriteSymlink) {
  const char kSymlinkTarget[] = "important_file";
  FilePath symlink_target_path = test_dir_.Append(kSymlinkTarget);
  const char kOriginalContents[] = "Very important contents";
  EXPECT_EQ(base::WriteFile(symlink_target_path, kOriginalContents,
                            strlen(kOriginalContents)),
            strlen(kOriginalContents));

  FilePath meta_symlink_path = test_dir_.Append("symlink.meta");
  ASSERT_EQ(0, symlink(kSymlinkTarget, meta_symlink_path.value().c_str()));
  ASSERT_TRUE(base::PathExists(meta_symlink_path));

  const char kPayloadName[] = "payload2-file";
  FilePath payload_file = test_dir_.Append(kPayloadName);
  ASSERT_TRUE(test_util::CreateFile(payload_file, "whatever"));

  brillo::ClearLog();
  collector_.FinishCrash(meta_symlink_path, "kernel", kPayloadName);
  // Target file contents should have stayed the same.
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(symlink_target_path, &contents));
  EXPECT_EQ(kOriginalContents, contents);
  EXPECT_TRUE(FindLog("Unable to write"));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

// Test target of dangling symlink is not created.
TEST_F(CrashCollectorTest, MetaDataDoesntCreateSymlink) {
  const char kSymlinkTarget[] = "important_file";
  FilePath symlink_target_path = test_dir_.Append(kSymlinkTarget);
  ASSERT_FALSE(base::PathExists(symlink_target_path));

  FilePath meta_symlink_path = test_dir_.Append("symlink.meta");
  ASSERT_EQ(0, symlink(kSymlinkTarget, meta_symlink_path.value().c_str()));
  ASSERT_FALSE(base::PathExists(meta_symlink_path));

  const char kPayloadName[] = "payload2-file";
  FilePath payload_file = test_dir_.Append(kPayloadName);
  ASSERT_TRUE(test_util::CreateFile(payload_file, "whatever"));

  brillo::ClearLog();
  collector_.FinishCrash(meta_symlink_path, "kernel", kPayloadName);
  EXPECT_FALSE(base::PathExists(symlink_target_path));
  EXPECT_TRUE(FindLog("Unable to write"));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
}

TEST_F(CrashCollectorTest, CollectionLogsToUMA) {
  auto metrics_lib = std::make_unique<MetricsLibraryMock>();
  MetricsLibraryMock* mock_ref = metrics_lib.get();
  collector_.set_metrics_library_for_test(std::move(metrics_lib));

  const FilePath kMetaFilePath = test_dir_.Append("meta.txt");
  const char kPayloadName[] = "payload-file";
  FilePath payload_file = test_dir_.Append(kPayloadName);

  EXPECT_CALL(*mock_ref, SendCrosEventToUMA("Crash.Collector.CollectionCount"))
      .WillOnce(Return(true));
  collector_.FinishCrash(kMetaFilePath, "kernel", kPayloadName);
}

TEST_F(CrashCollectorTest, GetLogContents) {
  FilePath config_file = test_dir_.Append("crash_config");
  FilePath output_file = test_dir_.Append("crash_log.gz");
  const char kConfigContents[] =
      "foobar=echo hello there | \\\n  sed -e \"s/there/world/\"";
  ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
  base::DeleteFile(FilePath(output_file));
  EXPECT_FALSE(collector_.GetLogContents(config_file, "barfoo", output_file));
  EXPECT_FALSE(base::PathExists(output_file));
  EXPECT_EQ(collector_.get_bytes_written(), 0);
  base::DeleteFile(FilePath(output_file));
  EXPECT_TRUE(collector_.GetLogContents(config_file, "foobar", output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  EXPECT_GT(collector_.get_bytes_written(), 0);

  int decompress_result = system(("gunzip " + output_file.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  FilePath decompressed_output_file = test_dir_.Append("crash_log");
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(decompressed_output_file, &contents));
  EXPECT_EQ("hello world\n", contents);
}

TEST_F(CrashCollectorTest, GetMultipleLogContents) {
  FilePath config_file = test_dir_.Append("crash_config");
  FilePath output_file = test_dir_.Append("crash_log");
  const char kConfigContents[] =
      "foobaz=echo foobaz\n"
      "bazbar=echo bazbar";
  ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
  base::DeleteFile(FilePath(output_file));

  // If both commands fail, expect no output.
  EXPECT_FALSE(collector_.GetMultipleLogContents(
      config_file, {"foobar", "barfoo"}, output_file));
  ASSERT_FALSE(base::PathExists(output_file));
  EXPECT_EQ(collector_.get_bytes_written(), 0);

  // If one command fails, expect output from the other command.
  EXPECT_TRUE(collector_.GetMultipleLogContents(
      config_file, {"foobar", "bazbar"}, output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  EXPECT_GT(collector_.get_bytes_written(), 0);
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(output_file, &contents));
  EXPECT_EQ("bazbar\n", contents);
  base::DeleteFile(FilePath(output_file));

  // Expect output from both commands.
  EXPECT_TRUE(collector_.GetMultipleLogContents(
      config_file, {"foobaz", "bazbar"}, output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  EXPECT_GT(collector_.get_bytes_written(), 0);
  EXPECT_TRUE(base::ReadFileToString(output_file, &contents));
  EXPECT_EQ("foobaz\nbazbar\n", contents);
}

TEST_F(CrashCollectorTest, GetProcessPath) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());
  FilePath path = collector_.GetProcessPath(100);
  ASSERT_EQ("/proc/100", path.value());
}

TEST_F(CrashCollectorTest, GetProcessTree) {
  // We want to use the real proc filesystem.
  paths::SetPrefixForTesting(base::FilePath());
  const FilePath output_file = test_dir_.Append("log");
  std::string contents;

  ASSERT_TRUE(collector_.GetProcessTree(getpid(), output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  EXPECT_TRUE(base::ReadFileToString(output_file, &contents));
  EXPECT_LT(300, contents.size()) << contents;
  EXPECT_EQ(collector_.get_bytes_written(), contents.size());
  base::DeleteFile(FilePath(output_file));

  ASSERT_TRUE(collector_.GetProcessTree(0, output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  std::string contents_pid_0;
  EXPECT_TRUE(base::ReadFileToString(output_file, &contents_pid_0));
  EXPECT_GT(100, contents_pid_0.size()) << contents_pid_0;
  EXPECT_EQ(collector_.get_bytes_written(),
            contents.size() + contents_pid_0.size());
}

TEST_F(CrashCollectorTest, TruncatedLog) {
  FilePath config_file = test_dir_.Append("crash_config");
  FilePath output_file = test_dir_.Append("crash_log.gz");
  const char kConfigContents[] = "foobar=echo These are log contents.";
  ASSERT_TRUE(test_util::CreateFile(config_file, kConfigContents));
  base::DeleteFile(FilePath(output_file));
  collector_.max_log_size_ = 10;
  EXPECT_TRUE(collector_.GetLogContents(config_file, "foobar", output_file));
  ASSERT_TRUE(base::PathExists(output_file));
  int64_t file_size = -1;
  EXPECT_TRUE(base::GetFileSize(output_file, &file_size));
  EXPECT_EQ(collector_.get_bytes_written(), file_size);

  int decompress_result = system(("gunzip " + output_file.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);

  FilePath decompressed_output_file = test_dir_.Append("crash_log");
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(decompressed_output_file, &contents));
  EXPECT_EQ("These are \n<TRUNCATED>\n", contents);
}

// Check that the mode is reset properly.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettingsMode) {
  int mode;
  EXPECT_TRUE(base::SetPosixFilePermissions(test_dir_, 0700));
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      test_dir_, 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::GetPosixFilePermissions(test_dir_, &mode));
  EXPECT_EQ(0755, mode);
}

// Check non-dir handling.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettingsNonDir) {
  const base::FilePath file = test_dir_.Append("file");

  // Do not walk past a non-dir.
  ASSERT_TRUE(test_util::CreateFile(file, ""));
  EXPECT_FALSE(CrashCollector::CreateDirectoryWithSettings(
      file.Append("subdir"), 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::PathExists(file));
  EXPECT_FALSE(base::DirectoryExists(file));

  // Remove files and create dirs.
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(file, 0755, getuid(),
                                                          getgid(), nullptr));
  EXPECT_TRUE(base::DirectoryExists(file));
}

// Check we only create a single subdir.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettingsSubdir) {
  const base::FilePath subdir = test_dir_.Append("sub");
  const base::FilePath subsubdir = subdir.Append("subsub");

  // Accessing sub/subsub/ should fail.
  EXPECT_FALSE(CrashCollector::CreateDirectoryWithSettings(
      subsubdir, 0755, getuid(), getgid(), nullptr));
  EXPECT_FALSE(base::PathExists(subdir));

  // Accessing sub/ should work.
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      subdir, 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::DirectoryExists(subdir));

  // Accessing sub/subsub/ should now work.
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      subsubdir, 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::DirectoryExists(subsubdir));
}

// Check symlink handling.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettingsSymlinks) {
  base::FilePath td;

  // Do not walk an intermediate symlink (final target doesn't exist).
  // test/sub/
  // test/sym -> sub
  // Then access test/sym/subsub/.
  td = test_dir_.Append("1");
  EXPECT_TRUE(base::CreateDirectory(td.Append("sub")));
  EXPECT_TRUE(
      base::CreateSymbolicLink(base::FilePath("sub"), td.Append("sym")));
  EXPECT_FALSE(CrashCollector::CreateDirectoryWithSettings(
      td.Append("sym1/subsub"), 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::IsLink(td.Append("sym")));
  EXPECT_FALSE(base::PathExists(td.Append("sub/subsub")));

  // Do not walk an intermediate symlink (final target exists).
  // test/sub/subsub/
  // test/sym -> sub
  // Then access test/sym/subsub/.
  td = test_dir_.Append("2");
  EXPECT_TRUE(base::CreateDirectory(td.Append("sub/subsub")));
  EXPECT_TRUE(
      base::CreateSymbolicLink(base::FilePath("sub"), td.Append("sym")));
  EXPECT_FALSE(CrashCollector::CreateDirectoryWithSettings(
      td.Append("sym/subsub"), 0755, getuid(), getgid(), nullptr));
  EXPECT_TRUE(base::IsLink(td.Append("sym")));

  // If the final path is a symlink, we should remove it and make a dir.
  // test/sub/
  // test/sub/sym -> subsub
  td = test_dir_.Append("3");
  EXPECT_TRUE(base::CreateDirectory(td.Append("sub/subsub")));
  EXPECT_TRUE(
      base::CreateSymbolicLink(base::FilePath("subsub"), td.Append("sub/sym")));
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      td.Append("sub/sym"), 0755, getuid(), getgid(), nullptr));
  EXPECT_FALSE(base::IsLink(td.Append("sub/sym")));
  EXPECT_TRUE(base::DirectoryExists(td.Append("sub/sym")));

  // If the final path is a symlink, we should remove it and make a dir.
  // test/sub/subsub
  // test/sub/sym -> subsub
  td = test_dir_.Append("4");
  EXPECT_TRUE(base::CreateDirectory(td.Append("sub")));
  EXPECT_TRUE(
      base::CreateSymbolicLink(base::FilePath("subsub"), td.Append("sub/sym")));
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      td.Append("sub/sym"), 0755, getuid(), getgid(), nullptr));
  EXPECT_FALSE(base::IsLink(td.Append("sub/sym")));
  EXPECT_TRUE(base::DirectoryExists(td.Append("sub/sym")));
  EXPECT_FALSE(base::PathExists(td.Append("sub/subsub")));
}

// Test that CreateDirectoryWithSettings only changes the directory if a file
// permission mode is not specified.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettings_FixPermissionsShallow) {
  FilePath crash_dir = test_dir_.Append("crash_perms");
  ASSERT_TRUE(base::CreateDirectory(crash_dir.Append("foo/bar")));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir, 0777));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo"), 0766));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo/bar"), 0744));

  const char contents[] = "hello";
  ASSERT_EQ(
      base::WriteFile(crash_dir.Append("file"), contents, strlen(contents)),
      strlen(contents));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("file"), 0600));

  int fd;
  int expected_mode = 0755;
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      crash_dir, expected_mode, getuid(), getgid(), &fd));
  struct stat st;
  EXPECT_EQ(fstat(fd, &st), 0);
  EXPECT_EQ(st.st_mode & 07777, expected_mode);

  close(fd);

  int actual_mode;
  EXPECT_TRUE(base::GetPosixFilePermissions(crash_dir, &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("file"), &actual_mode));
  EXPECT_EQ(actual_mode, 0600);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo"), &actual_mode));
  EXPECT_EQ(actual_mode, 0766);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo/bar"), &actual_mode));
  EXPECT_EQ(actual_mode, 0744);
}

// TODO(mutexlox): Test the following cases:
//   - Owner/Group changes are possible (may need to run as root?)
// Test that CreateDirectoryWithSettings fixes the permissions of a full tree.
TEST_F(CrashCollectorTest,
       CreateDirectoryWithSettings_FixPermissionsRecursive) {
  FilePath crash_dir = test_dir_.Append("crash_perms");
  ASSERT_TRUE(base::CreateDirectory(crash_dir.Append("foo/bar")));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir, 0777));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo"), 0766));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo/bar"), 0744));

  const char contents[] = "hello";
  ASSERT_EQ(
      base::WriteFile(crash_dir.Append("file"), contents, strlen(contents)),
      strlen(contents));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("file"), 0600));

  int fd;
  int expected_mode = 0755;
  int expected_file_mode = 0644;
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      crash_dir, expected_mode, getuid(), getgid(), &fd, expected_file_mode));
  struct stat st;
  EXPECT_EQ(fstat(fd, &st), 0);
  EXPECT_EQ(st.st_mode & 07777, expected_mode);

  close(fd);

  int actual_mode;
  EXPECT_TRUE(base::GetPosixFilePermissions(crash_dir, &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("file"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_file_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo/bar"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);
}

// Verify that CreateDirectoryWithSettings will fix subdirectories even if the
// top-level directory is correct.
TEST_F(CrashCollectorTest, CreateDirectoryWithSettings_FixSubdirPermissions) {
  FilePath crash_dir = test_dir_.Append("crash_perms");
  int expected_mode = 0755;

  ASSERT_TRUE(base::CreateDirectory(crash_dir.Append("foo/bar")));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir, expected_mode));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo"), 0766));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("foo/bar"), 0744));

  const char contents[] = "hello";
  ASSERT_EQ(
      base::WriteFile(crash_dir.Append("file"), contents, strlen(contents)),
      strlen(contents));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir.Append("file"), 0600));

  int fd;
  int expected_file_mode = 0644;
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      crash_dir, expected_mode, getuid(), getgid(), &fd, expected_file_mode));
  struct stat st;
  EXPECT_EQ(fstat(fd, &st), 0);
  EXPECT_EQ(st.st_mode & 07777, expected_mode);

  close(fd);

  int actual_mode;
  EXPECT_TRUE(base::GetPosixFilePermissions(crash_dir, &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("file"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_file_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);

  EXPECT_TRUE(
      base::GetPosixFilePermissions(crash_dir.Append("foo/bar"), &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);
}

TEST_F(CrashCollectorTest, RunAsRoot_CreateDirectoryWithSettings_FixOwners) {
  ASSERT_EQ(getuid(), 0);
  ASSERT_EQ(getgid(), 0);

  FilePath crash_dir = test_dir_.Append("crash_perms");
  ASSERT_TRUE(base::CreateDirectory(crash_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(crash_dir, 0777));

  ASSERT_EQ(chown(crash_dir.value().c_str(), 1001, 1001), 0);

  int fd;
  int expected_mode = 0755;
  EXPECT_TRUE(CrashCollector::CreateDirectoryWithSettings(
      crash_dir, expected_mode, getuid(), getgid(), &fd));
  struct stat st;
  EXPECT_EQ(fstat(fd, &st), 0);
  EXPECT_EQ(st.st_mode & 07777, expected_mode);
  EXPECT_EQ(st.st_uid, getuid());
  EXPECT_EQ(st.st_gid, getgid());

  close(fd);

  int actual_mode;
  EXPECT_TRUE(base::GetPosixFilePermissions(crash_dir, &actual_mode));
  EXPECT_EQ(actual_mode, expected_mode);
}

void CrashCollectorTest::TestFinishCrashInCrashLoopMode(
    bool give_success_response) {
  const char kBuffer[] = "Buffer full of goodness";
  const FilePath kPath = test_dir_.Append("buffer.txt");
  const FilePath kMetaFilePath = test_dir_.Append("meta.txt");
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  CrashCollectorMock collector(
      CrashCollector::kUseNormalCrashDirectorySelectionMethod,
      CrashCollector::kCrashLoopSendingMode);
  dbus::Bus::Options bus_options;
  auto mock_bus = base::MakeRefCounted<dbus::MockBus>(bus_options);
  auto mock_object_proxy = base::MakeRefCounted<dbus::MockObjectProxy>(
      mock_bus.get(), "org.chromium.debugd",
      dbus::ObjectPath("/org/chromium/debugd"));
  EXPECT_CALL(collector, SetUpDBus())
      .WillOnce(Invoke([&collector, &mock_bus]() {
        collector.bus_ = mock_bus;
        collector.debugd_proxy_ =
            std::make_unique<org::chromium::debugdProxy>(mock_bus);
      }))
      .WillRepeatedly(Return());
  EXPECT_CALL(*mock_bus,
              GetObjectProxy("org.chromium.debugd",
                             dbus::ObjectPath("/org/chromium/debugd")))
      .WillRepeatedly(Return(mock_object_proxy.get()));
  std::unique_ptr<dbus::Response> empty_response;
  std::unique_ptr<dbus::ErrorResponse> empty_error_response;
  EXPECT_CALL(*mock_object_proxy, DoCallMethodWithErrorCallback(_, 0, _, _))
      .WillOnce(Invoke([&](dbus::MethodCall* method_call, int timeout_ms,
                           dbus::ObjectProxy::ResponseCallback* callback,
                           dbus::ObjectProxy::ErrorCallback* error_callback) {
        // We can't copy or move the method_call object, and it will be
        // destroyed shortly after this lambda ends, so we must validate its
        // contents inside the lambda.
        dbus::MessageReader reader(method_call);
        dbus::MessageReader array_reader(nullptr);
        bool consent_already_checked = false;
        EXPECT_TRUE(reader.PopArray(&array_reader));
        EXPECT_TRUE(reader.PopBool(&consent_already_checked));
        EXPECT_FALSE(reader.HasMoreData());
        dbus::MessageReader struct_reader_1(nullptr);
        EXPECT_TRUE(array_reader.PopStruct(&struct_reader_1));
        dbus::MessageReader struct_reader_2(nullptr);
        EXPECT_TRUE(array_reader.PopStruct(&struct_reader_2));
        EXPECT_FALSE(array_reader.HasMoreData())
            << "Should only have 2 files in array";
        EXPECT_TRUE(consent_already_checked);

        std::string file_name_1;
        EXPECT_TRUE(struct_reader_1.PopString(&file_name_1));
        base::ScopedFD fd_1;
        EXPECT_TRUE(struct_reader_1.PopFileDescriptor(&fd_1));
        EXPECT_TRUE(fd_1.is_valid());
        EXPECT_FALSE(struct_reader_1.HasMoreData());

        std::string file_name_2;
        EXPECT_TRUE(struct_reader_2.PopString(&file_name_2));
        base::ScopedFD fd_2;
        EXPECT_TRUE(struct_reader_2.PopFileDescriptor(&fd_2));
        EXPECT_TRUE(fd_2.is_valid());
        EXPECT_FALSE(struct_reader_2.HasMoreData());

        base::ScopedFD payload_fd;
        base::ScopedFD meta_fd;
        if (file_name_1 == "buffer.txt") {
          EXPECT_EQ(file_name_2, "meta.txt");
          payload_fd = std::move(fd_1);
          meta_fd = std::move(fd_2);
        } else {
          EXPECT_EQ(file_name_1, "meta.txt");
          EXPECT_EQ(file_name_2, "buffer.txt");
          payload_fd = std::move(fd_2);
          meta_fd = std::move(fd_1);
        }
        base::File payload_file(payload_fd.release());
        EXPECT_TRUE(payload_file.IsValid());
        EXPECT_EQ(payload_file.GetLength(), strlen(kBuffer));
        char result_buffer[100] = {'\0'};
        EXPECT_EQ(payload_file.Read(0, result_buffer, sizeof(result_buffer)),
                  strlen(kBuffer));
        EXPECT_EQ(std::string(kBuffer), std::string(result_buffer));

        base::File meta_file(meta_fd.release());
        EXPECT_TRUE(meta_file.IsValid());
        EXPECT_GT(meta_file.GetLength(), 0);

        ASSERT_TRUE(base::SingleThreadTaskRunner::HasCurrentDefault());
        // Serial would normally be set by the transmission code before we tried
        // to make a reply from it. Since we are bypassing the transmission
        // code, we must set the serial number here.
        method_call->SetSerial(1);
        if (give_success_response) {
          empty_response = dbus::Response::FromMethodCall(method_call);
          base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
              FROM_HERE,
              base::BindOnce(std::move(*callback), empty_response.get()));
        } else {
          empty_error_response = dbus::ErrorResponse::FromMethodCall(
              method_call, "org.freedesktop.DBus.Error.Failed",
              "Things didn't work");
          base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
              FROM_HERE, base::BindOnce(std::move(*error_callback),
                                        empty_error_response.get()));
        }
      }));

  collector.Initialize(false);

  EXPECT_EQ(collector.WriteNewFile(kPath, kBuffer), strlen(kBuffer));
  EXPECT_EQ(collector.get_bytes_written(), strlen(kBuffer));
  collector.FinishCrash(kMetaFilePath, "kernel", kPath.BaseName().value());
  EXPECT_GT(collector.get_bytes_written(), strlen(kBuffer));
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           FinishCrashInCrashLoopModeSuccessfulResponse)) {
  TestFinishCrashInCrashLoopMode(true);
}

TEST_F(CrashCollectorTest,
       DISABLED_ON_QEMU_FOR_MEMFD_CREATE(
           FinishCrashInCrashLoopModeErrorResponse)) {
  TestFinishCrashInCrashLoopMode(false);
}

TEST_F(CrashCollectorTest, ComputeSeverity_DefaultUnspecified) {
  CrashCollector::ComputedCrashSeverity computed_severity =
      collector_.ComputeSeverity("test");

  EXPECT_EQ(computed_severity.crash_severity,
            CrashCollector::CrashSeverity::kUnspecified);
  EXPECT_EQ(computed_severity.product_group,
            CrashCollector::Product::kUnspecified);
}
