// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/missed_crash_collector.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

using ::testing::HasSubstr;
using ::testing::Return;

namespace {

class MissedCrashCollectorMock : public MissedCrashCollector {
 public:
  MissedCrashCollectorMock() : MissedCrashCollector() {}
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

void RunTestWithLogContents(base::StringPiece log_contents) {
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());

  base::FilePath input = tmp_dir.GetPath().Append("input.txt");
  base::WriteFile(input, log_contents.data(), log_contents.length());

  base::ScopedFILE input_file(fopen(input.value().c_str(), "r"));
  ASSERT_TRUE(input_file.get());

  MissedCrashCollectorMock collector;
  EXPECT_CALL(collector, SetUpDBus()).WillRepeatedly(Return());
  collector.set_crash_directory_for_test(tmp_dir.GetPath());
  collector.set_input_file_for_testing(input_file.get());
  collector.Initialize(false /*early*/);
  constexpr int kPid = 234;
  constexpr int kRecentMissCount = 5;
  constexpr int kRecentMatchCount = 2;
  constexpr int kPendingMissCount = 4;
  EXPECT_TRUE(collector.Collect(kPid, kRecentMissCount, kRecentMatchCount,
                                kPendingMissCount));

  base::FilePath meta_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "missed_crash.*.234.meta", &meta_path));
  base::FilePath log_path;
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      tmp_dir.GetPath(), "missed_crash.*.234.log.gz", &log_path));

  // Check log contents.
  int decompress_result = system(("gunzip " + log_path.value()).c_str());
  EXPECT_TRUE(WIFEXITED(decompress_result));
  EXPECT_EQ(WEXITSTATUS(decompress_result), 0);
  std::string actual_log_contents;
  EXPECT_TRUE(base::ReadFileToString(log_path.RemoveFinalExtension(),
                                     &actual_log_contents));
  EXPECT_EQ(log_contents, actual_log_contents);

  // Check meta contents.
  std::string meta_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_contents));
  EXPECT_THAT(
      meta_contents,
      HasSubstr(base::StrCat({"payload=", log_path.BaseName().value()})));
  EXPECT_THAT(meta_contents, HasSubstr("sig=missed-crash"));
  EXPECT_THAT(meta_contents, HasSubstr("upload_var_recent_miss_count=5"));
  EXPECT_THAT(meta_contents, HasSubstr("upload_var_recent_match_count=2"));
  EXPECT_THAT(meta_contents, HasSubstr("upload_var_pending_miss_count=4"));
  EXPECT_THAT(meta_contents, HasSubstr("upload_var_pid=234"));
  EXPECT_THAT(meta_contents, HasSubstr("done=1"));
}

}  // namespace

TEST(MissedCrashCollectorTest, Basic) {
  constexpr char kInput[] = R"(===stuff===
1 2 3
===more stuff===
hello
)";
  RunTestWithLogContents(kInput);
}
