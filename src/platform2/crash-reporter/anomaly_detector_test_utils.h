// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_ANOMALY_DETECTOR_TEST_UTILS_H_
#define CRASH_REPORTER_ANOMALY_DETECTOR_TEST_UTILS_H_

#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace anomaly {

struct CrashReport;
class Parser;

struct ParserRun {
  std::optional<std::string> find_this = std::nullopt;
  std::optional<std::string> replace_with = std::nullopt;
  std::optional<std::string> expected_text = std::nullopt;
  std::optional<std::vector<std::string>> expected_flags = std::nullopt;
  size_t expected_size = 1;
};

std::vector<CrashReport> ParseLogMessages(
    Parser* parser, const std::vector<std::string>& log_msgs);

void ReplaceMsgContent(std::vector<std::string>* log_msgs,
                       const std::string& find_this,
                       const std::string& replace_with);

std::vector<std::string> GetTestLogMessages(base::FilePath input_file);

void ParserTest(const std::string& input_file_name,
                std::initializer_list<ParserRun> parser_runs,
                anomaly::Parser* parser);

template <class T>
void ParserTest(const std::string& input_file_name,
                std::initializer_list<ParserRun> parser_runs) {
  T parser;
  ParserTest(input_file_name, parser_runs, &parser);
}

}  // namespace anomaly

#endif  // CRASH_REPORTER_ANOMALY_DETECTOR_TEST_UTILS_H_
