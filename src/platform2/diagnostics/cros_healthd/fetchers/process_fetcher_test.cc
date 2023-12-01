// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/process_fetcher.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/procfs_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

// POD struct for ParseProcessStateTest.
struct ParseProcessStateTestParams {
  std::string raw_state;
  mojom::ProcessState expected_mojo_state;
};

// ID of the process to be probed.
constexpr pid_t kPid = 6098;
constexpr pid_t kFirstPid = 6001;
constexpr pid_t kSecondPid = 6002;
constexpr pid_t kThirdPid = 6003;

// Valid fake data for /proc/uptime.
constexpr char kFakeProcUptimeContents[] = "339214.60 2707855.71";
// Incorrectly-formatted /proc/uptime file contents.
constexpr char kInvalidProcUptimeContents[] = "NotANumber 870.980";

// Valid fake data for /proc/|kPid/stat.
constexpr char kFakeProcPidStatContents[] =
    "6098 (fake_exe) S 1 1015 1015 0 -1 4210944 1536 158 1 0 10956 17428 19 37 "
    "20 0 1 0 358 36884480 3515";
constexpr char kFirstFakeProcPidStatContents[] =
    "6001 (first_fake_exe) S 1 1015 1015 0 -1 4210944 1536 158 1 0 10956 17428 "
    "19 37 20 0 1 0 358 36884480 3515";
constexpr char kSecondFakeProcPidStatContents[] =
    "6002 (second_fake_exe) S 1 1015 1015 0 -1 4210944 1536 158 1 0 10956 17428"
    " 19 37 20 0 1 0 358 36884480 3515";
constexpr char kThirdFakeProcPidStatContents[] =
    "6003 (third_fake_exe) S 1 1015 1015 0 -1 4210944 1536 158 1 0 10956 17428 "
    "19 37 20 0 1 0 358 36884480 3515";
// Data parsed from kFakeProcPidStatContents.
constexpr mojom::ProcessState kExpectedMojoState =
    mojom::ProcessState::kSleeping;
constexpr int8_t kExpectedPriority = 20;
constexpr int8_t kExpectedNice = 0;
constexpr char kExpectedName[] = "fake_exe";
constexpr char kFirstExpectedName[] = "first_fake_exe";
constexpr uint32_t kExpectedParentProcessID = 1;
constexpr uint32_t kExpectedProcessGroupID = 1015;
constexpr uint32_t kExpectedThreads = 1;
// Invalid /proc/|kPid|/stat: not enough tokens.
constexpr char kProcPidStatContentsInsufficientTokens[] =
    "6098 (fake_exe) S 1 1015 1015 0 -1 4210944";
// Invalid raw process state.
constexpr char kInvalidRawState[] = "InvalidState";
// Invalid priority value.
constexpr char kInvalidPriority[] = "InvalidPriority";
// Priority value too large to fit inside an 8-bit integer.
constexpr char kOverflowingPriority[] = "128";
// Invalid nice value.
constexpr char kInvalidNice[] = "InvalidNice";
// Invalid starttime value.
constexpr char kInvalidStarttime[] = "InvalidStarttime";
// Invalid parent process id value.
constexpr char kInvalidParentProcessID[] = "InvalidParentProcessID";
// Invalid process group id value.
constexpr char kInvalidProcessGroupID[] = "InvalidProcessGroupID";
// Invalid threads value.
constexpr char kInvalidThreads[] = "InvalidThreads";
// Invalid process id value.
constexpr char kInvalidProcessID[] = "InvalidProcessID";
// Valid fake data for /proc/|kPid|/statm.
constexpr char kFakeProcPidStatmContents[] = "25648 2657 2357 151 0 18632 0";
// Invalid /proc/|kPid|/statm: not enough tokens.
constexpr char kProcPidStatmContentsInsufficientTokens[] =
    "25648 2657 2357 151 0 18632";
// Invalid /proc/|kPid|/statm: total memory less than resident memory.
constexpr char kProcPidStatmContentsExcessiveResidentMemory[] =
    "2657 25648 2357 151 0 18632 0";
// Invalid /proc/|kPid|/statm: total memory overflows 32-bit unsigned int.
constexpr char kProcPidStatmContentsOverflowingTotalMemory[] =
    "4294967296 2657 2357 151 0 18632 0";
// Invalid /proc/|kPid|/statm: resident memory overflows 32-bit unsigned int.
constexpr char kProcPidStatmContentsOverflowingResidentMemory[] =
    "25648 4294967296 2357 151 0 18632 0";

// Valid fake data for /proc/|kPid|/io.
const std::vector<std::string> kFakeProcPidIOContents = {
    "rchar: 44846\n"
    "wchar: 10617\n"
    "syscr: 248\n"
    "syscw: 317\n"
    "read_bytes: 56799232\n"
    "write_bytes: 32768\n"
    "cancelled_write_bytes: 0"};

// Response of valid /proc/|kPid|/io from executor.
const base::flat_map<uint32_t, std::string> kFakeProcPidIOContentsResult = {
    {kPid, kFakeProcPidIOContents[0]}};
const base::flat_map<uint32_t, std::string>
    kFakeProcPidIOContentsMultipleResult = {
        {kFirstPid, kFakeProcPidIOContents[0]},
        {kSecondPid, kFakeProcPidIOContents[0]},
        {kThirdPid, kFakeProcPidIOContents[0]}};
const base::flat_map<uint32_t, std::string>
    kFakeProcPidIOContentsOnlyTwoResult = {
        {kFirstPid, kFakeProcPidIOContents[0]},
        {kThirdPid, kFakeProcPidIOContents[0]}};

// Data parsed from kFakeProcPidIOContents.
constexpr uint32_t kExpectedBytesRead = 44846;
constexpr uint32_t kExpectedBytesWritten = 10617;
constexpr uint32_t kExpectedReadSystemCalls = 248;
constexpr uint32_t kExpectedWriteSystemCalls = 317;
constexpr uint32_t kExpectedPhysicalBytesRead = 56799232;
constexpr uint32_t kExpectedPhysicalBytesWritten = 32768;
constexpr uint32_t kExpectedCancelledBytesWritten = 0;

// Invalid /proc/|kPid|/io: not enough fields.
const std::vector<std::string> kFakeProcPidIOContentsInsufficientFields = {
    "rchar: 44846\n"
    "wchar: 10617\n"
    "syscr: 248\n"
    "read_bytes: 56799232\n"
    "write_bytes: 32768\n"
    "cancelled_write_bytes: 0"};

// Response of invalid /proc/|kPid|/io from executor.
const base::flat_map<uint32_t, std::string>
    kFakeProcPidIOContentsInsufficientFieldsResult = {
        {kPid, kFakeProcPidIOContentsInsufficientFields[0]}};
const base::flat_map<uint32_t, std::string>
    kFakeProcPidIOContentsInsufficientFieldsMultipleResult = {
        {kFirstPid, kFakeProcPidIOContents[0]},
        {kSecondPid, kFakeProcPidIOContentsInsufficientFields[0]},
        {kThirdPid, kFakeProcPidIOContents[0]}};

// Valid fake data for /proc/|kPid|/status.
constexpr char kFakeProcPidStatusContents[] =
    "Name:\tfake_exe\nState:\tS (sleeping)\nUid:\t20104 20104 20104 20104\n";
// Data parsed from kFakeProcPidStatusContents.
constexpr uint32_t kExpectedUid = 20104;
// Invalid /proc/|kPid|/status contents: Uid key not present.
constexpr char kProcPidStatusContentsNoUidKey[] =
    "Name:\tfake_exe\nState:\tS (sleeping)\n";
// Invalid /proc/|kPid|/status contents: Uid key doesn't have four values.
constexpr char kProcPidStatusContentsNotEnoughUidValues[] =
    "Name:\tfake_exe\nState:\tS (sleeping)\nUid:\t20104 20104 20104\n";
// Invalid /proc/|kPid|/status contents: Uid key value is negative.
constexpr char kProcPidStatusContentsNegativeUidValue[] =
    "Name:\tfake_exe\nState:\tS (sleeping)\nUid:\t-20104 20104 20104 20104\n";

// Valid fake data for /proc/|kPid|/cmdline. Note that this is an arbitrary
// string, so there is no invalid data for this file.
constexpr char kFakeProcPidCmdlineContents[] = "/usr/bin/fake_exe --arg=yes";

class ProcessFetcherTest : public testing::Test {
 protected:
  ProcessFetcherTest() = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    // Set up valid files for the processes with PID |kPid|, |kFirstPid|,
    // |kSecondPid|, |kThirdPid|. Individual tests are expected to override this
    // configuration when necessary.

    // Write /proc/uptime.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcUptimePath(temp_dir_path()),
                                             kFakeProcUptimeContents));

    WriteFiles(kPid, kFakeProcPidStatContents);
    WriteFiles(kFirstPid, kFirstFakeProcPidStatContents);
    WriteFiles(kSecondPid, kSecondFakeProcPidStatContents);
    WriteFiles(kThirdPid, kThirdFakeProcPidStatContents);
  }

  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  mojom::ProcessResultPtr FetchProcessInfo() {
    base::test::TestFuture<mojom::ProcessResultPtr> future;
    ProcessFetcher(&mock_context_, temp_dir_path())
        .FetchProcessInfo(kPid, future.GetCallback());
    return future.Take();
  }

  mojom::MultipleProcessResultPtr FetchMultipleProcessInfo(bool ignore) {
    base::test::TestFuture<mojom::MultipleProcessResultPtr> future;
    std::vector<uint32_t> pids{kFirstPid, kSecondPid, kThirdPid};
    ProcessFetcher(&mock_context_, temp_dir_path())
        .FetchMultipleProcessInfo(pids, ignore, future.GetCallback());
    return future.Take();
  }

  bool WriteProcPidStatData(const std::string& new_data,
                            ProcPidStatIndices index,
                            const pid_t pid) {
    // Tokenize the fake /proc/|pid|/stat data.
    std::vector<std::string> tokens =
        base::SplitString(kFakeProcPidStatContents, " ", base::TRIM_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY);

    // Shove in the new data.
    tokens[index] = new_data;

    // Reconstruct the fake data in the correct format.
    std::string new_fake_data;
    for (const auto& token : tokens)
      new_fake_data = new_fake_data + token + " ";

    // Write the new fake data.
    return WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessStatFile),
        new_fake_data);
  }

  void ExpectAndSetExecutorGetProcessIOContentsResponse(
      const base::flat_map<uint32_t, std::string>& io_contents) {
    // Set the mock executor response.
    EXPECT_CALL(*mock_context_.mock_executor(), GetProcessIOContents(_, _))
        .WillOnce(WithArg<1>(
            Invoke([=](mojom::Executor::GetProcessIOContentsCallback callback) {
              base::flat_map<uint32_t, std::string> content;
              content = io_contents;
              std::move(callback).Run(content);
            })));
  }

  const base::FilePath& temp_dir_path() const { return temp_dir_.GetPath(); }

 private:
  void WriteFiles(pid_t pid, const char fake_proc_pid_stat_contents[]) {
    // Write /proc/|pid|/stat.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessStatFile),
        fake_proc_pid_stat_contents));
    // Write /proc/|pid|/statm.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessStatmFile),
        kFakeProcPidStatmContents));
    // Write /proc/|pid|/io.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessIOFile),
        kFakeProcPidIOContents[0]));
    // Write /proc/|pid|/status.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessStatusFile),
        kFakeProcPidStatusContents));
    // Write /proc/|pid|/cmdline.
    ASSERT_TRUE(WriteFileAndCreateParentDirs(
        GetProcProcessDirectoryPath(temp_dir_path(), pid)
            .Append(kProcessCmdlineFile),
        kFakeProcPidCmdlineContents));
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  base::ScopedTempDir temp_dir_;
  MockContext mock_context_;
};

// Test that process info can be read when it exists.
TEST_F(ProcessFetcherTest, FetchProcessInfo) {
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsResult);
  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_process_info());
  const auto& process_info = process_result->get_process_info();
  EXPECT_EQ(process_info->command, kFakeProcPidCmdlineContents);
  EXPECT_EQ(process_info->user_id, kExpectedUid);
  EXPECT_EQ(process_info->priority, kExpectedPriority);
  EXPECT_EQ(process_info->nice, kExpectedNice);
  // TODO(crbug/1105605): Test the expected uptime, once it no longer depends on
  // sysconf.
  EXPECT_EQ(process_info->state, kExpectedMojoState);
  EXPECT_EQ(process_info->bytes_read, kExpectedBytesRead);
  EXPECT_EQ(process_info->bytes_written, kExpectedBytesWritten);
  EXPECT_EQ(process_info->read_system_calls, kExpectedReadSystemCalls);
  EXPECT_EQ(process_info->write_system_calls, kExpectedWriteSystemCalls);
  EXPECT_EQ(process_info->physical_bytes_read, kExpectedPhysicalBytesRead);
  EXPECT_EQ(process_info->physical_bytes_written,
            kExpectedPhysicalBytesWritten);
  EXPECT_EQ(process_info->cancelled_bytes_written,
            kExpectedCancelledBytesWritten);
  EXPECT_EQ(process_info->name, kExpectedName);
  EXPECT_EQ(process_info->parent_process_id, kExpectedParentProcessID);
  EXPECT_EQ(process_info->process_group_id, kExpectedProcessGroupID);
  EXPECT_EQ(process_info->threads, kExpectedThreads);
  EXPECT_EQ(process_info->process_id, kPid);
}

// Test that we handle a missing /proc/uptime file.
TEST_F(ProcessFetcherTest, MissingProcUptimeFile) {
  ASSERT_TRUE(brillo::DeleteFile(GetProcUptimePath(temp_dir_path())));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle an incorrectly-formatted /proc/uptime file.
TEST_F(ProcessFetcherTest, IncorrectlyFormattedProcUptimeFile) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(GetProcUptimePath(temp_dir_path()),
                                           kInvalidProcUptimeContents));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a missing /proc/|kPid|/cmdline file.
TEST_F(ProcessFetcherTest, MissingProcPidCmdlineFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetProcProcessDirectoryPath(temp_dir_path(), kPid)
                             .Append(kProcessCmdlineFile)));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, MissingProcPidStatFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetProcProcessDirectoryPath(temp_dir_path(), kPid)
                             .Append(kProcessStatFile)));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing /proc/|kPid|/statm file.
TEST_F(ProcessFetcherTest, MissingProcPidStatmFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetProcProcessDirectoryPath(temp_dir_path(), kPid)
                             .Append(kProcessStatmFile)));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle a missing /proc/|kPid|/io file.
TEST_F(ProcessFetcherTest, MissingProcPidIOFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetProcProcessDirectoryPath(temp_dir_path(), kPid)
                             .Append(kProcessIOFile)));
  ExpectAndSetExecutorGetProcessIOContentsResponse({});

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle a /proc/|kPid|/stat file with insufficient tokens.
TEST_F(ProcessFetcherTest, ProcPidStatFileInsufficientTokens) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatFile),
      kProcPidStatContentsInsufficientTokens));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid state read from the /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, InvalidProcessStateRead) {
  ASSERT_TRUE(
      WriteProcPidStatData(kInvalidRawState, ProcPidStatIndices::kState, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid priority read from the /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, InvalidProcessPriorityRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidPriority,
                                   ProcPidStatIndices::kPriority, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid nice value read from the /proc/|kPid|/stat
// file.
TEST_F(ProcessFetcherTest, InvalidProcessNiceRead) {
  ASSERT_TRUE(
      WriteProcPidStatData(kInvalidNice, ProcPidStatIndices::kNice, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we can handle an overflowing priority value from the
// /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, OverflowingPriorityRead) {
  ASSERT_TRUE(WriteProcPidStatData(kOverflowingPriority,
                                   ProcPidStatIndices::kPriority, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid starttime read from the /proc/|kPid|/stat
// file.
TEST_F(ProcessFetcherTest, InvalidProcessStarttimeRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidStarttime,
                                   ProcPidStatIndices::kStartTime, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid parent process id value read from the
// /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, InvalidParentProcessIDRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidParentProcessID,
                                   ProcPidStatIndices::kParentProcessID, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid process group id value read from the
// /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, InvalidProcessGroupIDRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidProcessGroupID,
                                   ProcPidStatIndices::kProcessGroupID, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid threads value read from the /proc/|kPid|/stat
// file.
TEST_F(ProcessFetcherTest, InvalidThreadsRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidThreads,
                                   ProcPidStatIndices::kThreads, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle an invalid process id value read from the
// /proc/|kPid|/stat file.
TEST_F(ProcessFetcherTest, InvalidProcessIDRead) {
  ASSERT_TRUE(WriteProcPidStatData(kInvalidProcessID,
                                   ProcPidStatIndices::kProcessID, kPid));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/statm file with insufficient tokens.
TEST_F(ProcessFetcherTest, ProcPidStatmFileInsufficientTokens) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatmFile),
      kProcPidStatmContentsInsufficientTokens));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/statm file with an invalid total memory
// value.
TEST_F(ProcessFetcherTest, ProcPidStatmFileInvalidTotalMemory) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatmFile),
      kProcPidStatmContentsOverflowingTotalMemory));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/statm file with an invalid resident memory
// value.
TEST_F(ProcessFetcherTest, ProcPidStatmFileInvalidResidentMemory) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatmFile),
      kProcPidStatmContentsOverflowingResidentMemory));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/io file with insufficient fields.
TEST_F(ProcessFetcherTest, ProcPidIOFileInsufficientTokens) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid).Append(kProcessIOFile),
      kFakeProcPidIOContentsInsufficientFields[0]));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsInsufficientFieldsResult);

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/statm file with resident memory value
// higher than the total memory value.
TEST_F(ProcessFetcherTest, ProcPidStatmFileExcessiveResidentMemory) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatmFile),
      kProcPidStatmContentsExcessiveResidentMemory));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a missing /proc/|kPid|/status file.
TEST_F(ProcessFetcherTest, MissingProcPidStatusFile) {
  ASSERT_TRUE(
      brillo::DeleteFile(GetProcProcessDirectoryPath(temp_dir_path(), kPid)
                             .Append(kProcessStatusFile)));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type,
            mojom::ErrorType::kFileReadError);
}

// Test that we handle a /proc/|kPid|/status file which doesn't have the Uid
// key.
TEST_F(ProcessFetcherTest, ProcPidStatusFileNoUidKey) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatusFile),
      kProcPidStatusContentsNoUidKey));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/status file with a Uid key with less than
// four values.
TEST_F(ProcessFetcherTest, ProcPidStatusFileUidKeyInsufficientValues) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatusFile),
      kProcPidStatusContentsNotEnoughUidValues));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that we handle a /proc/|kPid|/status file with a Uid key with negative
// values.
TEST_F(ProcessFetcherTest, ProcPidStatusFileUidKeyWithNegativeValues) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kPid)
          .Append(kProcessStatusFile),
      kProcPidStatusContentsNegativeUidValue));

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_error());
  EXPECT_EQ(process_result->get_error()->type, mojom::ErrorType::kParseError);
}

// Test that multiple process info can be read when all exists.
TEST_F(ProcessFetcherTest, FetchMultipleProcessInfo) {
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsMultipleResult);
  auto process_result = FetchMultipleProcessInfo(false);

  ASSERT_TRUE(process_result->errors.empty());
  EXPECT_EQ(process_result->process_infos.size(), 3);
  // Ensure all three process info match input process ids, and only verify
  // |kFirstPid|'s detailed content.
  EXPECT_TRUE(process_result->process_infos.count(kFirstPid));
  EXPECT_TRUE(process_result->process_infos.count(kSecondPid));
  EXPECT_TRUE(process_result->process_infos.count(kThirdPid));
  auto& first_pid_process_info =
      process_result->process_infos.find(kFirstPid)->second;
  EXPECT_EQ(first_pid_process_info->command, kFakeProcPidCmdlineContents);
  EXPECT_EQ(first_pid_process_info->user_id, kExpectedUid);
  EXPECT_EQ(first_pid_process_info->priority, kExpectedPriority);
  EXPECT_EQ(first_pid_process_info->nice, kExpectedNice);
  EXPECT_EQ(first_pid_process_info->state, kExpectedMojoState);
  EXPECT_EQ(first_pid_process_info->bytes_read, kExpectedBytesRead);
  EXPECT_EQ(first_pid_process_info->bytes_written, kExpectedBytesWritten);
  EXPECT_EQ(first_pid_process_info->read_system_calls,
            kExpectedReadSystemCalls);
  EXPECT_EQ(first_pid_process_info->write_system_calls,
            kExpectedWriteSystemCalls);
  EXPECT_EQ(first_pid_process_info->physical_bytes_read,
            kExpectedPhysicalBytesRead);
  EXPECT_EQ(first_pid_process_info->physical_bytes_written,
            kExpectedPhysicalBytesWritten);
  EXPECT_EQ(first_pid_process_info->cancelled_bytes_written,
            kExpectedCancelledBytesWritten);
  EXPECT_EQ(first_pid_process_info->name, kFirstExpectedName);
  EXPECT_EQ(first_pid_process_info->parent_process_id,
            kExpectedParentProcessID);
  EXPECT_EQ(first_pid_process_info->process_group_id, kExpectedProcessGroupID);
  EXPECT_EQ(first_pid_process_info->threads, kExpectedThreads);
  EXPECT_EQ(first_pid_process_info->process_id, kFirstPid);
}

// Test that we handle a missing /proc/|kSecondPid|/stat file while ignoring
// single process errors.
TEST_F(ProcessFetcherTest, MissingProcPidStatFileMultipleProcessIgnoreError) {
  ASSERT_TRUE(brillo::DeleteFile(
      GetProcProcessDirectoryPath(temp_dir_path(), kSecondPid)
          .Append(kProcessStatFile)));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsOnlyTwoResult);
  auto process_result = FetchMultipleProcessInfo(true);

  ASSERT_TRUE(process_result->errors.empty());
  EXPECT_EQ(process_result->process_infos.size(), 2);
  EXPECT_TRUE(process_result->process_infos.count(kFirstPid));
  EXPECT_TRUE(process_result->process_infos.count(kThirdPid));
}

// Test that we handle a missing /proc/|kSecondPid|/stat file while not ignoring
// single process errors.
TEST_F(ProcessFetcherTest, MissingProcPidStatFileMultipleProcess) {
  ASSERT_TRUE(brillo::DeleteFile(
      GetProcProcessDirectoryPath(temp_dir_path(), kSecondPid)
          .Append(kProcessStatFile)));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsOnlyTwoResult);
  auto process_result = FetchMultipleProcessInfo(false);

  EXPECT_EQ(process_result->errors.size(), 1);
  EXPECT_EQ(process_result->errors.find(kSecondPid)->second->type,
            mojom::ErrorType::kFileReadError);
  EXPECT_EQ(process_result->process_infos.size(), 2);
  EXPECT_TRUE(process_result->process_infos.count(kFirstPid));
  EXPECT_TRUE(process_result->process_infos.count(kThirdPid));
}

// Test that we handle a /proc/|kSecondPid|/io file with insufficient fields
// while not ignoring single process errors.
TEST_F(ProcessFetcherTest, ProcPidIOFileInsufficientTokensMultipleProcess) {
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      GetProcProcessDirectoryPath(temp_dir_path(), kSecondPid)
          .Append(kProcessIOFile),
      kFakeProcPidIOContentsInsufficientFields[0]));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsInsufficientFieldsMultipleResult);

  auto process_result = FetchMultipleProcessInfo(false);

  EXPECT_EQ(process_result->errors.size(), 1);
  EXPECT_EQ(process_result->errors.find(kSecondPid)->second->type,
            mojom::ErrorType::kParseError);
  EXPECT_EQ(process_result->process_infos.size(), 2);
  EXPECT_TRUE(process_result->process_infos.count(kFirstPid));
  EXPECT_TRUE(process_result->process_infos.count(kThirdPid));
}

// Test that we handle a missing /proc/|kSecondPid|/io file while not ignoring
// single process errors.
TEST_F(ProcessFetcherTest, MissingProcPidIOFileMultipleProcess) {
  ASSERT_TRUE(brillo::DeleteFile(
      GetProcProcessDirectoryPath(temp_dir_path(), kSecondPid)
          .Append(kProcessIOFile)));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsOnlyTwoResult);

  auto process_result = FetchMultipleProcessInfo(false);

  EXPECT_EQ(process_result->errors.size(), 1);
  EXPECT_EQ(process_result->errors.find(kSecondPid)->second->type,
            mojom::ErrorType::kFileReadError);
  EXPECT_EQ(process_result->process_infos.size(), 2);
  EXPECT_TRUE(process_result->process_infos.count(kFirstPid));
  EXPECT_TRUE(process_result->process_infos.count(kThirdPid));
}

// Tests that ProcessFetcher can correctly parse each process state.
//
// This is a parameterized test with the following parameters (accessed
// through the ParseProcessStateTestParams POD struct):
// * |raw_state| - written to /proc/|kPid|/stat's process state field.
// * |expected_mojo_state| - expected value of the returned ProcessInfo's state
//                           field.
class ParseProcessStateTest
    : public ProcessFetcherTest,
      public testing::WithParamInterface<ParseProcessStateTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  ParseProcessStateTestParams params() const { return GetParam(); }
};

// Test that we can parse the given process state.
TEST_P(ParseProcessStateTest, ParseState) {
  ASSERT_TRUE(WriteProcPidStatData(params().raw_state,
                                   ProcPidStatIndices::kState, kPid));
  ExpectAndSetExecutorGetProcessIOContentsResponse(
      kFakeProcPidIOContentsResult);

  auto process_result = FetchProcessInfo();

  ASSERT_TRUE(process_result->is_process_info());
  EXPECT_EQ(process_result->get_process_info()->state,
            params().expected_mojo_state);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ParseProcessStateTest,
    testing::Values(ParseProcessStateTestParams{/*raw_state=*/"R",
                                                mojom::ProcessState::kRunning},
                    ParseProcessStateTestParams{/*raw_state=*/"S",
                                                mojom::ProcessState::kSleeping},
                    ParseProcessStateTestParams{/*raw_state=*/"D",
                                                mojom::ProcessState::kWaiting},
                    ParseProcessStateTestParams{/*raw_state=*/"Z",
                                                mojom::ProcessState::kZombie},
                    ParseProcessStateTestParams{/*raw_state=*/"T",
                                                mojom::ProcessState::kStopped},
                    ParseProcessStateTestParams{
                        /*raw_state=*/"t", mojom::ProcessState::kTracingStop},
                    ParseProcessStateTestParams{/*raw_state=*/"X",
                                                mojom::ProcessState::kDead},
                    ParseProcessStateTestParams{/*raw_state=*/"I",
                                                mojom::ProcessState::kIdle}));

}  // namespace
}  // namespace diagnostics
