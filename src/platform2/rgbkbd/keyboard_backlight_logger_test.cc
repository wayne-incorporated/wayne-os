// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "rgbkbd/keyboard_backlight_logger.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/strcat.h"

namespace rgbkbd {

namespace {

const char kTempLogFilePath[] = "/tmp/rgbkbd_log";

}  // namespace

class KeyboardBacklightLoggerTest : public testing::Test {
 public:
  KeyboardBacklightLoggerTest() {
    // Default to RgbKeyboardCapabilities::kIndividualKey
    logger_ = std::make_unique<KeyboardBacklightLogger>(
        base::FilePath(kTempLogFilePath),
        RgbKeyboardCapabilities::kIndividualKey);
  }

  KeyboardBacklightLoggerTest(const KeyboardBacklightLoggerTest&) = delete;
  KeyboardBacklightLoggerTest& operator=(const KeyboardBacklightLoggerTest&) =
      delete;
  ~KeyboardBacklightLoggerTest() override = default;

 protected:
  std::unique_ptr<KeyboardBacklightLogger> logger_;
};

TEST_F(KeyboardBacklightLoggerTest, SetKeyColorLog) {
  const std::string expected_log = base::StrCat(
      {"RGB::SetKeyColor - ", std::to_string(55), ",", std::to_string(255), ",",
       std::to_string(0), ",", std::to_string(10), "\n"});

  logger_->SetKeyColor(/*key=*/55, /*r=*/255, /*g=*/0, /*b=*/10);

  const base::FilePath path(kTempLogFilePath);
  EXPECT_TRUE(base::PathExists(path));

  int64_t file_size = 0u;
  EXPECT_TRUE(base::GetFileSize(path, &file_size));
  EXPECT_EQ(expected_log.length(), file_size);

  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(path, &file_contents));
  EXPECT_EQ(expected_log, file_contents);
}

TEST_F(KeyboardBacklightLoggerTest, SetAllKeyColorsLog) {
  const std::string expected_log =
      base::StrCat({"RGB::SetAllKeyColors - ", std::to_string(255), ",",
                    std::to_string(0), ",", std::to_string(10), "\n"});

  logger_->SetAllKeyColors(/*r=*/255, /*g=*/0, /*b=*/10);

  const base::FilePath path(kTempLogFilePath);
  EXPECT_TRUE(base::PathExists(path));

  int64_t file_size = 0u;
  EXPECT_TRUE(base::GetFileSize(path, &file_size));
  EXPECT_EQ(expected_log.length(), file_size);

  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(path, &file_contents));
  EXPECT_EQ(expected_log, file_contents);
}

TEST_F(KeyboardBacklightLoggerTest, MultipleLogs) {
  const std::string expected_log1 = base::StrCat(
      {"RGB::SetKeyColor - ", std::to_string(55), ",", std::to_string(255), ",",
       std::to_string(0), ",", std::to_string(10), "\n"});
  EXPECT_TRUE(logger_->SetKeyColor(/*key=*/55, /*r=*/255, /*g=*/0, /*b=*/10));

  const base::FilePath path(kTempLogFilePath);
  EXPECT_TRUE(base::PathExists(path));

  int64_t file_size = 0u;
  EXPECT_TRUE(base::GetFileSize(path, &file_size));
  EXPECT_EQ(expected_log1.length(), file_size);

  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(path, &file_contents));
  EXPECT_EQ(expected_log1, file_contents);

  // Now try another log.
  const std::string expected_log2 =
      base::StrCat({"RGB::SetAllKeyColors - ", std::to_string(255), ",",
                    std::to_string(0), ",", std::to_string(10), "\n"});
  EXPECT_TRUE(logger_->SetAllKeyColors(/*r=*/255, /*g=*/0, /*b=*/10));

  file_size = 0u;
  EXPECT_TRUE(base::GetFileSize(path, &file_size));
  EXPECT_EQ(expected_log1.length() + expected_log2.length(), file_size);

  file_contents = "";
  EXPECT_TRUE(base::ReadFileToString(path, &file_contents));
  EXPECT_EQ(expected_log1 + expected_log2, file_contents);
}
}  // namespace rgbkbd
