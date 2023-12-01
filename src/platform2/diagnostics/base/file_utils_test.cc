// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>

#include <base/strings/string_number_conversions.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/base/file_utils.h"

namespace diagnostics {
namespace {

const auto kFileNameTest = "test";
const auto kFileNameTestInt = "test_int";
const auto kFileNameNotExist = "not_exist";

const auto kDataStr = "\r  test\n  ";
const auto kExpectedStr = "test";
const auto kDataNumber = "\r  42\n  ";
const auto kExpectedNumber = 42;

class FileUtilsTest : public BaseFileTest {
 protected:
  void SetUp() override {
    SetFile(kFileNameTest, kDataStr);
    SetFile(kFileNameTestInt, kDataNumber);
  }
};

TEST_F(FileUtilsTest, ReadAndTrimString) {
  std::string str;
  ASSERT_TRUE(ReadAndTrimString(root_dir(), kFileNameTest, &str));
  EXPECT_EQ(str, kExpectedStr);
  ASSERT_TRUE(ReadAndTrimString(GetPathUnderRoot(kFileNameTest), &str));
  EXPECT_EQ(str, kExpectedStr);

  ASSERT_FALSE(ReadAndTrimString(root_dir(), kFileNameNotExist, &str));

  std::optional<std::string> opt_str;
  ASSERT_TRUE(ReadAndTrimString(root_dir(), kFileNameTest, &opt_str));
  ASSERT_TRUE(opt_str.has_value());
  EXPECT_EQ(opt_str.value(), kExpectedStr);
}

TEST_F(FileUtilsTest, ReadInteger) {
  int num;
  ASSERT_TRUE(
      ReadInteger(root_dir(), kFileNameTestInt, &base::StringToInt, &num));
  EXPECT_EQ(num, kExpectedNumber);
  ASSERT_TRUE(ReadInteger(GetPathUnderRoot(kFileNameTestInt),
                          &base::StringToInt, &num));
  EXPECT_EQ(num, kExpectedNumber);

  ASSERT_FALSE(
      ReadInteger(root_dir(), kFileNameTest, &base::StringToInt, &num));
  ASSERT_FALSE(
      ReadInteger(root_dir(), kFileNameNotExist, &base::StringToInt, &num));
}

TEST(FileUtilsDirectTest, RootDirWithoutOverridden) {
  EXPECT_EQ(GetRootDir(), base::FilePath{"/"});
  EXPECT_EQ(GetRootedPath(base::FilePath{"/"}), base::FilePath{"/"});
  EXPECT_EQ(GetRootedPath(base::FilePath{"/abc"}), base::FilePath{"/abc"});
  EXPECT_EQ(GetRootedPath("/abc"), base::FilePath{"/abc"});
}

}  // namespace
}  // namespace diagnostics
