// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/dev_features_password_utils.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <brillo/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

// Override any functions in DevFeaturesPassword that won't work properly
// during unit testing. File creation/modification should still work and
// can be tested directly.
class TestDevFeaturesPasswordUtils : public debugd::DevFeaturesPasswordUtils {
 public:
  TestDevFeaturesPasswordUtils() = default;
  ~TestDevFeaturesPasswordUtils() override = default;

  // openssl may not be usable so we need to mock this function.
  MOCK_METHOD(bool,
              HashPassword,
              (const std::string&, std::string*),
              (override));
};

const char kTestPassword[] = "test0000";
const char kTestPasswordHashed[] = "$1$c2edOizq$bjtHnO.Ob6cd3dkwkXYLD/";

}  // namespace

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::Test;

class DevFeaturesPasswordHelperTest : public Test {
 public:
  DevFeaturesPasswordHelperTest() {
    ON_CALL(utils_, HashPassword(kTestPassword, _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(kTestPasswordHashed), Return(true)));
    // Start with an empty temp directory but no password file.
    CHECK(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().Append("password.temp");
  }

 protected:
  TestDevFeaturesPasswordUtils utils_;
  base::ScopedTempDir temp_dir_;
  base::FilePath file_path_;

  // Writes |contents| to password_file_path_.
  bool WritePasswordFile(const std::string& contents) {
    int length = contents.length();
    return base::WriteFile(file_path_, contents.c_str(), length) == length;
  }

  // Deletes the password file if it exists.
  void DeletePasswordFile() { brillo::DeleteFile(file_path_); }

  // Creates a password file with valid entries for chronos and root users.
  bool MakeValidPasswordFile() {
    return WritePasswordFile(base::StringPrintf(
        "root:%s\nchronos:%s\n", kTestPasswordHashed, kTestPasswordHashed));
  }

  // Creates a password file with invalid entries for chronos and root users.
  bool MakeInvalidPasswordFile() {
    return WritePasswordFile("root::\nchronos:*\n");
  }
};

TEST_F(DevFeaturesPasswordHelperTest, ValidUsernameTest) {
  EXPECT_TRUE(utils_.IsUsernameValid("root"));
  EXPECT_TRUE(utils_.IsUsernameValid("chronos"));
  EXPECT_TRUE(utils_.IsUsernameValid("CHRONOS"));
  EXPECT_FALSE(utils_.IsUsernameValid(":root"));
  EXPECT_FALSE(utils_.IsUsernameValid("root:"));
  EXPECT_FALSE(utils_.IsUsernameValid("root chronos"));
}

TEST_F(DevFeaturesPasswordHelperTest, QueryValidPasswords) {
  EXPECT_TRUE(MakeValidPasswordFile());
  EXPECT_TRUE(utils_.IsPasswordSet("root", file_path_));
  EXPECT_TRUE(utils_.IsPasswordSet("chronos", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("notauser", file_path_));
}

TEST_F(DevFeaturesPasswordHelperTest, QueryInvalidPasswords) {
  EXPECT_TRUE(MakeInvalidPasswordFile());
  EXPECT_FALSE(utils_.IsPasswordSet("root", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("chronos", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("notauser", file_path_));
}

TEST_F(DevFeaturesPasswordHelperTest, QueryEmptyPasswordFile) {
  EXPECT_TRUE(WritePasswordFile(""));
  EXPECT_FALSE(utils_.IsPasswordSet("root", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("chronos", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("notauser", file_path_));
}

TEST_F(DevFeaturesPasswordHelperTest, QueryNoPasswordFile) {
  EXPECT_FALSE(utils_.IsPasswordSet("root", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("chronos", file_path_));
  EXPECT_FALSE(utils_.IsPasswordSet("notauser", file_path_));
}

TEST_F(DevFeaturesPasswordHelperTest, SetNoPasswordFile) {
  EXPECT_TRUE(utils_.SetPassword("root", kTestPassword, file_path_));
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(file_path_, &contents));
  EXPECT_EQ(base::StringPrintf("root:%s:::::::\n", kTestPasswordHashed),
            contents);
}

TEST_F(DevFeaturesPasswordHelperTest, SetPreviouslySetPassword) {
  EXPECT_TRUE(MakeValidPasswordFile());
  std::string original_contents, new_contents;
  EXPECT_TRUE(base::ReadFileToString(file_path_, &original_contents));
  EXPECT_TRUE(utils_.SetPassword("root", kTestPassword, file_path_));
  EXPECT_TRUE(base::ReadFileToString(file_path_, &new_contents));
  EXPECT_EQ(original_contents, new_contents);
}

TEST_F(DevFeaturesPasswordHelperTest, SetOverwriteInvalidPasswords) {
  EXPECT_TRUE(MakeInvalidPasswordFile());
  EXPECT_TRUE(utils_.SetPassword("root", kTestPassword, file_path_));
  EXPECT_TRUE(utils_.SetPassword("chronos", kTestPassword, file_path_));
  EXPECT_TRUE(utils_.IsPasswordSet("root", file_path_));
  EXPECT_TRUE(utils_.IsPasswordSet("chronos", file_path_));
}
