// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <metrics/metrics_library_mock.h>

#include "diagnostics/cros_minidiag/elog_manager.h"
#include "diagnostics/cros_minidiag/minidiag_metrics.h"
#include "diagnostics/cros_minidiag/utils.h"

namespace cros_minidiag {

namespace {
constexpr const char kMockFileName[] = "last-line";
}  // namespace

class UtilsFuzzer {
 public:
  UtilsFuzzer() {
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    path_ = scoped_temp_dir_.GetPath().Append(kMockFileName);
    minidiag_metrics_.SetMetricsLibraryForTesting(&mock_metrics_library_);
  }

  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath path_;
  testing::StrictMock<MetricsLibraryMock> mock_metrics_library_;
  MiniDiagMetrics minidiag_metrics_;
};

}  // namespace cros_minidiag

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  cros_minidiag::UtilsFuzzer fuzzer;
  FuzzedDataProvider data_provider(data, size);
  std::string previous_last_line;

  const auto fuzz_line = data_provider.ConsumeRandomLengthString();
  std::string fuzz_line_trim;
  base::TrimWhitespaceASCII(fuzz_line, base::TRIM_TRAILING, &fuzz_line_trim);
  CHECK(base::WriteFile(fuzzer.path_, fuzz_line));

  // Fuzz test of GetPrevElogLastLine.
  if (fuzz_line.size() > cros_minidiag::kMaxFileSize ||
      !base::IsStringASCII(fuzz_line)) {
    // If the size of file is suspiciously large or the input contains non-ASCII
    // characters, the function should fail.
    CHECK(
        !cros_minidiag::GetPrevElogLastLine(fuzzer.path_, previous_last_line));
    CHECK(previous_last_line.empty());
  } else {
    CHECK(cros_minidiag::GetPrevElogLastLine(fuzzer.path_, previous_last_line));
    CHECK_EQ(previous_last_line, fuzz_line_trim);
  }

  // Fuzz test of ElogManager ctor.
  auto elog_manager = std::make_unique<cros_minidiag::ElogManager>(
      data_provider.ConsumeRandomLengthString(), previous_last_line,
      &fuzzer.minidiag_metrics_);
  elog_manager->ReportMiniDiagLaunch();
  elog_manager->ReportMiniDiagTestReport();

  return 0;
}
