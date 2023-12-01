// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

#include "diagnostics/wilco_dtc_supportd/utils/file_test_utils.h"

namespace diagnostics {
namespace wilco {
namespace {

constexpr char kTestBinaryFile[] = "/usr/local/test.bin";
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

TEST_F(FileTest, BaseTest) {
  // Tests absolute path
  SetFile("/a/b/c", "c");
  CheckFile("a/b/c", "c");
  // Tests relative path
  SetFile("d/e/f", "f");
  CheckFile("d/e/f", "f");
  // Tests deleting dir
  UnsetPath("a");
  EXPECT_FALSE(PathExists(GetPathUnderRoot("a")));
  // Tests deleting file
  UnsetPath("/d/e/f");
  EXPECT_FALSE(PathExists(GetPathUnderRoot("d/e/f")));
  // Tests deleting not exist file
  UnsetPath("not/exist/file");

  // Tests |base::FilePath|
  SetFile(base::FilePath("text.txt"), "file_content");
  CheckFile("text.txt", "file_content");
  // Tests constexpr and |base::span|
  SetFile(kTestBinaryFile, base::span{kTestBinaryData});
  CheckFile(kTestBinaryFile,
            std::string(reinterpret_cast<const char*>(kTestBinaryData),
                        kTestBinaryDataLen));

  const auto expected_path = root_dir().Append("a/b/c");
  EXPECT_EQ(GetPathUnderRoot("a/b/c"), expected_path);
  EXPECT_EQ(GetPathUnderRoot("/a/b/c"), expected_path);
  EXPECT_EQ(GetPathUnderRoot(base::FilePath("/a/b/c")), expected_path);
  EXPECT_EQ(GetPathUnderRoot(base::FilePath("a/b/c")), expected_path);
  EXPECT_EQ(GetPathUnderRoot({"a", "b", "c"}), expected_path);
  EXPECT_EQ(GetPathUnderRoot({"/a", "b/c"}), expected_path);
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
