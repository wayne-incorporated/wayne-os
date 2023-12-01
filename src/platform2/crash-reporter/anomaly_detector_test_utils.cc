// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector_test_utils.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/anomaly_detector.h"
#include "crash-reporter/test_util.h"

using ::testing::HasSubstr;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAreArray;

namespace anomaly {

std::vector<anomaly::CrashReport> ParseLogMessages(
    anomaly::Parser* parser, const std::vector<std::string>& log_msgs) {
  std::vector<anomaly::CrashReport> crash_reports;
  for (auto& msg : log_msgs) {
    auto crash_report = parser->ParseLogEntry(msg);
    if (crash_report)
      crash_reports.push_back(std::move(*crash_report));
  }
  return crash_reports;
}

void ReplaceMsgContent(std::vector<std::string>* log_msgs,
                       const std::string& find_this,
                       const std::string& replace_with) {
  for (auto& msg : *log_msgs)
    base::ReplaceSubstringsAfterOffset(&msg, 0, find_this, replace_with);
}

std::vector<std::string> GetTestLogMessages(base::FilePath input_file) {
  std::string contents;
  // Though ASSERT would be better here, we need to use EXPECT since functions
  // calling ASSERT must return void.
  EXPECT_TRUE(base::ReadFileToString(input_file, &contents));
  auto log_msgs = base::SplitString(contents, "\n", base::KEEP_WHITESPACE,
                                    base::SPLIT_WANT_ALL);
  EXPECT_GT(log_msgs.size(), 0);
  if (log_msgs.size() == 0) {
    return log_msgs;
  }
  // Handle likely newline at end of file.
  if (log_msgs.back().empty())
    log_msgs.pop_back();
  return log_msgs;
}

void ParserTest(const std::string& input_file_name,
                std::initializer_list<ParserRun> parser_runs,
                anomaly::Parser* parser) {
  auto log_msgs =
      GetTestLogMessages(test_util::GetTestDataPath(input_file_name,
                                                    /*use_testdata=*/true));
  for (auto& run : parser_runs) {
    if (run.find_this && run.replace_with)
      ReplaceMsgContent(&log_msgs, *run.find_this, *run.replace_with);
    auto crash_reports = ParseLogMessages(parser, log_msgs);

    ASSERT_THAT(crash_reports, SizeIs(run.expected_size));
    if (run.expected_text)
      EXPECT_THAT(crash_reports[0].text, HasSubstr(*run.expected_text));
    if (run.expected_flags)
      EXPECT_THAT(crash_reports[0].flags,
                  UnorderedElementsAreArray(*run.expected_flags));
  }
}

}  // namespace anomaly
