// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/timezone_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kLocaltimeFile[] = "var/lib/timezone/localtime";
constexpr char kZoneInfoPath[] = "usr/share/zoneinfo";
constexpr char kTimezoneRegion[] = "America/Denver";
constexpr char kPosixTimezoneFile[] = "MST.tzif";
constexpr char kPosixTimezoneOutput[] = "MST7MDT,M3.2.0,M11.1.0";
constexpr char kSrcPath[] = "cros_healthd/fetchers";

class TimezoneFetcherTest : public ::testing::Test {
 protected:
  TimezoneFetcherTest() = default;
  TimezoneFetcherTest(const TimezoneFetcherTest&) = delete;
  TimezoneFetcherTest& operator=(const TimezoneFetcherTest&) = delete;

  const base::FilePath& root_dir() { return mock_context_.root_dir(); }

  mojom::TimezoneResultPtr FetchTimezoneInfo() {
    return timezone_fetcher_.FetchTimezoneInfo();
  }

 private:
  MockContext mock_context_;
  TimezoneFetcher timezone_fetcher_{&mock_context_};
};

// Test the logic to get and parse the timezone information.
TEST_F(TimezoneFetcherTest, TestGetTimezone) {
  // Create files and symlinks expected to be present for the localtime file.
  base::FilePath timezone_file_path =
      root_dir().AppendASCII(kZoneInfoPath).AppendASCII(kTimezoneRegion);
  base::FilePath localtime_path = root_dir().AppendASCII(kLocaltimeFile);

  ASSERT_TRUE(
      WriteFileAndCreateSymbolicLink(timezone_file_path, "", localtime_path));

  base::FilePath test_file = base::FilePath(getenv("SRC"))
                                 .AppendASCII(kSrcPath)
                                 .AppendASCII(kPosixTimezoneFile);
  ASSERT_TRUE(base::CopyFile(test_file, timezone_file_path));

  auto result = FetchTimezoneInfo();
  ASSERT_TRUE(result->is_timezone_info());

  const auto& info = result->get_timezone_info();
  EXPECT_EQ(info->posix, kPosixTimezoneOutput);
  EXPECT_EQ(info->region, kTimezoneRegion);
}

// Test that the function fails gracefully if the files do not exist.
TEST_F(TimezoneFetcherTest, TestGetTimezoneFailure) {
  auto result = FetchTimezoneInfo();
  ASSERT_TRUE(result->is_error());
  EXPECT_EQ(result->get_error()->type, mojom::ErrorType::kFileReadError);
}

}  // namespace
}  // namespace diagnostics
