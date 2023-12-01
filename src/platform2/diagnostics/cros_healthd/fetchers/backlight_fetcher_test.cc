// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/backlight_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

using ::ash::cros_healthd::mojom::BacklightInfo;
using ::ash::cros_healthd::mojom::BacklightInfoPtr;
using ::ash::cros_healthd::mojom::BacklightResultPtr;
using ::ash::cros_healthd::mojom::ErrorType;
using ::testing::UnorderedElementsAreArray;

constexpr char kRelativeBacklightDirectoryPath[] = "sys/class/backlight";
constexpr char kBrightnessFileName[] = "brightness";
constexpr char kMaxBrightnessFileName[] = "max_brightness";

constexpr uint32_t kFirstFakeBacklightBrightness = 98;
constexpr uint32_t kFirstFakeBacklightMaxBrightness = 99;
constexpr uint32_t kSecondFakeBacklightBrightness = 12;
constexpr uint32_t kSecondFakeBacklightMaxBrightness = 43;
constexpr char kFakeNonIntegerFileContents[] = "Not an integer!";

base::FilePath GetFirstFakeBacklightDirectory(const base::FilePath& root) {
  return root.Append(kRelativeBacklightDirectoryPath).Append("first_dir");
}

base::FilePath GetSecondFakeBacklightDirectory(const base::FilePath& root) {
  return root.Append(kRelativeBacklightDirectoryPath).Append("second_dir");
}

// Workaround for UnorderedElementsAreArray not accepting move-only types - this
// simple matcher expects a std::cref(mojom::BacklightInfoPtr) and checks
// each of the three fields for equality.
MATCHER_P(MatchesBacklightInfoPtr, ptr, "") {
  return arg->path == ptr.get()->path &&
         arg->max_brightness == ptr.get()->max_brightness &&
         arg->brightness == ptr.get()->brightness;
}

class BacklightUtilsTest : public ::testing::Test {
 protected:
  BacklightUtilsTest() = default;
  BacklightUtilsTest(const BacklightUtilsTest&) = delete;
  BacklightUtilsTest& operator=(const BacklightUtilsTest&) = delete;

  BacklightResultPtr FetchBacklightInfo() {
    return backlight_fetcher_.FetchBacklightInfo();
  }

  void SetHasBacklight(const bool val) {
    mock_context_.fake_system_config()->SetHasBacklight(val);
  }

  const base::FilePath& root_dir() { return mock_context_.root_dir(); }

 private:
  MockContext mock_context_;
  BacklightFetcher backlight_fetcher_{&mock_context_};
};

// Test that backlight info can be read when it exists.
TEST_F(BacklightUtilsTest, TestFetchBacklightInfo) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightMaxBrightness)));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightBrightness)));
  base::FilePath second_backlight_dir =
      GetSecondFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      second_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kSecondFakeBacklightMaxBrightness)));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      second_backlight_dir.Append(kBrightnessFileName),
      base::NumberToString(kSecondFakeBacklightBrightness)));

  std::vector<BacklightInfoPtr> expected_results;
  expected_results.push_back(BacklightInfo::New(
      first_backlight_dir.value(), kFirstFakeBacklightMaxBrightness,
      kFirstFakeBacklightBrightness));
  expected_results.push_back(BacklightInfo::New(
      second_backlight_dir.value(), kSecondFakeBacklightMaxBrightness,
      kSecondFakeBacklightBrightness));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_backlight_info());
  const auto& backlight_info = backlight_result->get_backlight_info();

  // Since FetchBacklightInfo uses base::FileEnumerator, we're not guaranteed
  // the order of the two results.
  EXPECT_THAT(backlight_info,
              UnorderedElementsAreArray({
                  MatchesBacklightInfoPtr(std::cref(expected_results[0])),
                  MatchesBacklightInfoPtr(std::cref(expected_results[1])),
              }));
}

// Test that one bad backlight directory (missing required files) returns an
// error.
TEST_F(BacklightUtilsTest, TestFetchBacklightInfoOneBadOneGoodDirectory) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  // Skip the brightness file for the first directory.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightMaxBrightness)));
  base::FilePath second_backlight_dir =
      GetSecondFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      second_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kSecondFakeBacklightMaxBrightness)));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      second_backlight_dir.Append(kBrightnessFileName),
      base::NumberToString(kSecondFakeBacklightBrightness)));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that fetching backlight info returns an error when no backlight
// directories exist, but the device has a backlight.
TEST_F(BacklightUtilsTest, TestFetchBacklightInfoNoDirectories) {
  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that fetching backlight info returns an error when the brightness file
// doesn't exist.
TEST_F(BacklightUtilsTest, TestFetchBacklightInfoNoBrightness) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightMaxBrightness)));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that fetching backlight info returns an error when the max_brightness
// file doesn't exist.
TEST_F(BacklightUtilsTest, TestFetchBacklightInfoNoMaxBrightness) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightBrightness)));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that fetching backlight info returns an error when the brightess file is
// formatted incorrectly.
TEST_F(BacklightUtilsTest,
       TestFetchBacklightInfoBrightnessFormattedIncorrectly) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kMaxBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightMaxBrightness)));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kBrightnessFileName),
      kFakeNonIntegerFileContents));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that fetching backlight info returns an error when the max_brightess
// file is formatted incorrectly.
TEST_F(BacklightUtilsTest,
       TestFetchBacklightInfoMaxBrightnessFormattedIncorrectly) {
  base::FilePath first_backlight_dir =
      GetFirstFakeBacklightDirectory(root_dir());
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kMaxBrightnessFileName),
      kFakeNonIntegerFileContents));
  ASSERT_TRUE(WriteFileAndCreateParentDirs(
      first_backlight_dir.Append(kBrightnessFileName),
      base::NumberToString(kFirstFakeBacklightMaxBrightness)));

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_error());
  EXPECT_EQ(backlight_result->get_error()->type, ErrorType::kFileReadError);
}

// Test that we return an empty BacklightInfo list when cros_config says it
// doesn't exist.
TEST_F(BacklightUtilsTest, TestCrosConfigReportsNoBacklight) {
  SetHasBacklight(false);

  auto backlight_result = FetchBacklightInfo();
  ASSERT_TRUE(backlight_result->is_backlight_info());
  EXPECT_EQ(backlight_result->get_backlight_info().size(), 0);
}

}  // namespace
}  // namespace diagnostics
