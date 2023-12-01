// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/file_reader.h"

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>

namespace cros_disks {

class FileReaderTest : public ::testing::Test {
 public:
  void VerifyReadLines(const base::FilePath& path,
                       const std::vector<std::string>& lines) {
    std::string line;
    EXPECT_FALSE(reader_.ReadLine(&line));
    EXPECT_TRUE(reader_.Open(path));
    for (const auto& expected_line : lines) {
      EXPECT_TRUE(reader_.ReadLine(&line));
      EXPECT_EQ(expected_line, line);
    }
    EXPECT_FALSE(reader_.ReadLine(&line));
    reader_.Close();
    EXPECT_FALSE(reader_.ReadLine(&line));
  }

 protected:
  FileReader reader_;
};

TEST_F(FileReaderTest, OpenNonExistentFile) {
  EXPECT_FALSE(reader_.Open(base::FilePath("a_nonexistent_file")));
}

TEST_F(FileReaderTest, OpenEmptyFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir.GetPath(), &path));

  EXPECT_TRUE(reader_.Open(path));
  std::string line;
  EXPECT_FALSE(reader_.ReadLine(&line));
  reader_.Close();
}

TEST_F(FileReaderTest, ReadLine) {
  std::vector<std::string> lines;
  lines.push_back("this is");
  lines.push_back("a");
  lines.push_back("");
  lines.push_back("test");
  std::string content = base::JoinString(lines, "\n");

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_dir.GetPath(), &path));

  // Test a file not ending with a new-line character
  ASSERT_EQ(content.size(),
            base::WriteFile(path, content.c_str(), content.size()));
  VerifyReadLines(path, lines);

  // Test a file ending with a new-line character
  content.push_back('\n');
  ASSERT_EQ(content.size(),
            base::WriteFile(path, content.c_str(), content.size()));
  VerifyReadLines(path, lines);
}

}  // namespace cros_disks
