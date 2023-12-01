// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/file_test_utils.h"

namespace runtime_probe {
namespace {

constexpr unsigned char kTestBinaryData[] = {0x01, 0x23, 0x45, 0x67,
                                             0x89, 0xab, 0xcd, 0xef};
constexpr size_t kTestBinaryDataLen = 8;

class FileTest : public BaseFileTest {
 protected:
  void SetUp() override { CreateTestRoot(); }

  void CheckFile(const std::string& path, const std::string& expect) {
    std::string content;
    ASSERT_TRUE(base::ReadFileToString(GetPathUnderRoot(path), &content));
    EXPECT_EQ(content, expect);
  }
};

TEST_F(FileTest, PathType) {
  base::FilePath expected = base::FilePath{"/a/b/c"};
  auto test_fun = [](const PathType& path) { return path.file_path(); };

  EXPECT_EQ(test_fun("/a/b/c"), expected);
  EXPECT_EQ(test_fun("/a/b/c"), expected);
  EXPECT_EQ(test_fun(std::string{"/a/b/c"}), expected);
  EXPECT_EQ(test_fun(expected), expected);
  EXPECT_EQ(test_fun({"/a", "b", "c"}), expected);
  EXPECT_EQ(test_fun({"/a", "b/c"}), expected);
  // Relative path.
  EXPECT_NE(test_fun({"a", "b", "c"}), expected);
}

TEST_F(FileTest, BaseTest) {
  // Tests absolute path
  SetFile("/a/b/c", "c");
  CheckFile("a/b/c", "c");
  // Tests relative path
  SetFile("d/e/f", "f");
  CheckFile("d/e/f", "f");
  // Tests deleting dir
  UnsetPath("a");
  EXPECT_FALSE(base::PathExists(GetPathUnderRoot("a")));
  // Tests deleting file
  UnsetPath("/d/e/f");
  EXPECT_FALSE(base::PathExists(GetPathUnderRoot("d/e/f")));
  // Tests deleting not exist file
  UnsetPath("not/exist/file");

  // Tests |base::span|
  SetFile("test.bin", base::span{kTestBinaryData});
  CheckFile("test.bin",
            std::string(reinterpret_cast<const char*>(kTestBinaryData),
                        kTestBinaryDataLen));

  const auto expected_path = root_dir().Append("a/b/c");
  EXPECT_EQ(GetPathUnderRoot("a/b/c"), expected_path);
  EXPECT_EQ(GetPathUnderRoot("/a/b/c"), expected_path);

  SetDirectory("my/dir");
  EXPECT_TRUE(base::DirectoryExists(GetPathUnderRoot("my/dir")));
}

}  // namespace
}  // namespace runtime_probe
