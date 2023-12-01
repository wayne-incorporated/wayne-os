// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_rotator/log_rotator.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

namespace log_rotator {

namespace {
std::string ReadFile(const base::FilePath& path) {
  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(path, &file_content));
  return file_content;
}

}  // namespace

class LogRotatorTest : public ::testing::Test {
 public:
  LogRotatorTest() = default;
  LogRotatorTest(const LogRotatorTest&) = delete;
  LogRotatorTest& operator=(const LogRotatorTest&) = delete;
};

TEST_F(LogRotatorTest, GetFilePathWithIndex) {
  {
    LogRotator rotator(base::FilePath("test"));

    EXPECT_EQ(base::FilePath("test.1"), rotator.GetFilePathWithIndex(1));

    EXPECT_EQ(base::FilePath("test"), rotator.GetFilePathWithIndex(0));
  }

  {
    LogRotator rotator(base::FilePath("test.log"));
    EXPECT_EQ(base::FilePath("test.log"), rotator.GetFilePathWithIndex(0));
    EXPECT_EQ(base::FilePath("test.2.log"), rotator.GetFilePathWithIndex(2));
  }

  {
    LogRotator rotator(base::FilePath("test.error.txt.log"));
    EXPECT_EQ(base::FilePath("test.error.txt.log"),
              rotator.GetFilePathWithIndex(0));
    EXPECT_EQ(base::FilePath("test.error.txt.2.log"),
              rotator.GetFilePathWithIndex(2));
  }

  {
    LogRotator rotator(base::FilePath("test.3.log"));
    EXPECT_EQ(base::FilePath("test.3.4.log"), rotator.GetFilePathWithIndex(4));
    EXPECT_EQ(base::FilePath("test.3.log"), rotator.GetFilePathWithIndex(0));
  }

  {
    // Base path with storange extensions. We shouldn't use filenames like this
    // but test it.
    LogRotator rotator(base::FilePath("test..log"));
    EXPECT_EQ(base::FilePath("test..4.log"), rotator.GetFilePathWithIndex(4));
    EXPECT_EQ(base::FilePath("test..log"), rotator.GetFilePathWithIndex(0));
  }

  {
    // Base path with storange extensions. We shouldn't use filenames like this
    // but test it.
    LogRotator rotator(base::FilePath("test.."));
    EXPECT_EQ(base::FilePath("test..4."), rotator.GetFilePathWithIndex(4));
    EXPECT_EQ(base::FilePath("test.."), rotator.GetFilePathWithIndex(0));
  }
}

TEST_F(LogRotatorTest, GetIndexFromFilePath) {
  {
    // Base path without any extension.
    LogRotator rotator(base::FilePath("test"));

    // Valid patterns:
    EXPECT_EQ(0, rotator.GetIndexFromFilePath(base::FilePath("test")));
    EXPECT_EQ(1, rotator.GetIndexFromFilePath(base::FilePath("test.1")));

    // Invalid patterns:
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.0")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.1.log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.log.1")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.2.3")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("tes.1")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("testt.1")));
  }

  {
    // Base path with an extension.
    LogRotator rotator(base::FilePath("test.txt.log"));

    // Valid patterns:
    EXPECT_EQ(0, rotator.GetIndexFromFilePath(base::FilePath("test.txt.log")));
    EXPECT_EQ(1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.1.log")));

    // Invalid patterns:
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.0.log")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.0.log.1")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.1.log.0")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.1.log.1")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.0.txt.log")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.1.txt.log")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.log.0")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.log.1")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt_1_log")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt_1.log")));
    EXPECT_EQ(-1,
              rotator.GetIndexFromFilePath(base::FilePath("test.txt.1_log")));
  }

  {
    // Base path with two extensions.
    LogRotator rotator(base::FilePath("test.9.log"));

    // Valid patterns:
    EXPECT_EQ(0, rotator.GetIndexFromFilePath(base::FilePath("test.9.log")));
    EXPECT_EQ(1, rotator.GetIndexFromFilePath(base::FilePath("test.9.1.log")));

    // Invalid patterns:
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.9.0.log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.1.9.log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.0.9.log")));
  }

  {
    // Base path with storange extensions. We shouldn't use filenames like this
    // but test it.
    LogRotator rotator(base::FilePath("test..log"));

    // Valid patterns:
    EXPECT_EQ(0, rotator.GetIndexFromFilePath(base::FilePath("test..log")));
    EXPECT_EQ(1, rotator.GetIndexFromFilePath(base::FilePath("test..1.log")));

    // Invalid patterns:
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test..0.log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.0..log")));
    EXPECT_EQ(-1, rotator.GetIndexFromFilePath(base::FilePath("test.1..log")));
  }

  {
    // Base path with storange extensions. We shouldn't use filenames like this
    // but test it.
    LogRotator rotator(base::FilePath("test..."));
    EXPECT_EQ(0, rotator.GetIndexFromFilePath(base::FilePath("test...")));
    EXPECT_EQ(1, rotator.GetIndexFromFilePath(base::FilePath("test...1.")));
  }
}

TEST_F(LogRotatorTest, CleanUpFiles) {
  {
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

    const char* files[]{"test",      "test.1",      "test.2",
                        "test.hoge", "test.fuga.1", "testt.log"};
    base::FilePath base_file_path = temp_dir.GetPath().Append(files[0]);

    for (int i = 0; i < std::size(files); ++i)
      base::WriteFile(temp_dir.GetPath().Append(files[i]), "x", 1);

    LogRotator rotator(base_file_path);
    rotator.CleanUpFiles(1);
    EXPECT_TRUE(base::PathExists(temp_dir.GetPath().Append(files[0])));
    EXPECT_TRUE(base::PathExists(temp_dir.GetPath().Append(files[1])));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append(files[2])));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append(files[3])));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append(files[4])));
    EXPECT_TRUE(base::PathExists(temp_dir.GetPath().Append(files[5])));
  }
}

TEST_F(LogRotatorTest, RotateLogFile) {
  // Normal rotation:
  {
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

    base::FilePath base_file_path = temp_dir.GetPath().Append("test");
    base::WriteFile(base_file_path, "0", 1);

    for (int i = 1; i < 5; ++i) {
      std::string number = base::NumberToString(i);
      base::WriteFile(temp_dir.GetPath().Append("test." + number),
                      number.c_str(), 1);
    }

    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_EQ("3", ReadFile(temp_dir.GetPath().Append("test.3")));
    EXPECT_EQ("4", ReadFile(temp_dir.GetPath().Append("test.4")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));

    LogRotator rotator(base_file_path);
    rotator.RotateLogFile(10);

    EXPECT_EQ("", ReadFile(base_file_path));
    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.3")));
    EXPECT_EQ("3", ReadFile(temp_dir.GetPath().Append("test.4")));
    EXPECT_EQ("4", ReadFile(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.6")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));
  }

  // Rotation with exceeding the limit. The older files should be removed.
  {
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

    base::FilePath base_file_path = temp_dir.GetPath().Append("test");
    base::WriteFile(base_file_path, "0", 1);

    for (int i = 1; i < 5; ++i) {
      std::string number = base::NumberToString(i);
      base::WriteFile(temp_dir.GetPath().Append("test." + number),
                      number.c_str(), 1);
    }

    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_EQ("3", ReadFile(temp_dir.GetPath().Append("test.3")));
    EXPECT_EQ("4", ReadFile(temp_dir.GetPath().Append("test.4")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));

    LogRotator rotator(base_file_path);
    rotator.RotateLogFile(3);

    EXPECT_EQ("", ReadFile(base_file_path));
    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.3")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.4")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.6")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));
  }

  // Rotation with missing log file. In this case, "test.3" is missing.
  {
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

    base::FilePath base_file_path = temp_dir.GetPath().Append("test");
    base::WriteFile(base_file_path, "0", 1);

    for (int i = 1; i < 5; ++i) {
      if (i == 3)
        continue;
      std::string number = base::NumberToString(i);
      base::WriteFile(temp_dir.GetPath().Append("test." + number),
                      number.c_str(), 1);
    }

    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.3")));
    EXPECT_EQ("4", ReadFile(temp_dir.GetPath().Append("test.4")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));

    LogRotator rotator(base_file_path);
    rotator.RotateLogFile(5);

    EXPECT_EQ("", ReadFile(base_file_path));
    EXPECT_EQ("0", ReadFile(temp_dir.GetPath().Append("test.1")));
    EXPECT_EQ("1", ReadFile(temp_dir.GetPath().Append("test.2")));
    EXPECT_EQ("2", ReadFile(temp_dir.GetPath().Append("test.3")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.4")));
    EXPECT_EQ("4", ReadFile(temp_dir.GetPath().Append("test.5")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.6")));
    EXPECT_FALSE(base::PathExists(temp_dir.GetPath().Append("test.0")));
  }
}

TEST_F(LogRotatorTest, RotateLogFileWithInheritingPermission) {
  {
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());

    constexpr int FILE_MODE = S_IRUSR | S_IXOTH;

    base::FilePath base_file_path = temp_dir.GetPath().Append("test");
    base::WriteFile(base_file_path, "0", 1);
    base::SetPosixFilePermissions(base_file_path, FILE_MODE);

    int mode;
    EXPECT_TRUE(base::GetPosixFilePermissions(base_file_path, &mode));
    EXPECT_EQ(FILE_MODE, mode);

    LogRotator rotator(base_file_path);
    rotator.RotateLogFile(2);

    EXPECT_TRUE(base::GetPosixFilePermissions(base_file_path, &mode));
    EXPECT_EQ(FILE_MODE, mode);
    EXPECT_TRUE(base::GetPosixFilePermissions(
        temp_dir.GetPath().Append("test.1"), &mode));
    EXPECT_EQ(FILE_MODE, mode);
  }
}

}  // namespace log_rotator
