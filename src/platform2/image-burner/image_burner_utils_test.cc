// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "image-burner/image_burner_utils.h"

#include <sys/sysmacros.h>

#include <string>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <gtest/gtest.h>

namespace imageburn {

namespace {

const int kTestDataBufferSize = 100;

}  // namespace

class BurnReaderTest : public ::testing::Test {
 public:
  BurnReaderTest() {}
  BurnReaderTest(const BurnReaderTest&) = delete;
  BurnReaderTest& operator=(const BurnReaderTest&) = delete;

  ~BurnReaderTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(test_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(
        base::CreateTemporaryFileInDir(test_dir_.GetPath(), &test_file_path_));
  }

 protected:
  bool SetTestFileContent(const std::string& content) {
    const int written =
        base::WriteFile(test_file_path_, content.data(), content.size());
    return written >= 0 && static_cast<size_t>(written) == content.size();
  }

  BurnReader file_reader_;

  base::ScopedTempDir test_dir_;
  base::FilePath test_file_path_;
};

class BurnWriterTest : public ::testing::Test {
 public:
  BurnWriterTest() {}
  BurnWriterTest(const BurnWriterTest&) = delete;
  BurnWriterTest& operator=(const BurnWriterTest&) = delete;

  ~BurnWriterTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(test_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(
        base::CreateTemporaryFileInDir(test_dir_.GetPath(), &test_file_path_));
  }

  int FakeBlockDeviceFstat(int fd, base::stat_wrapper_t* st) {
    if (!file_writer_.file().IsValid())
      return -1;
    EXPECT_EQ(file_writer_.file().GetPlatformFile(), fd);
    st->st_rdev = makedev(14, 7);
    st->st_mode = S_IFBLK;
    return 0;
  }

  int FailingFstat(int fd, base::stat_wrapper_t* st) {
    EXPECT_EQ(file_writer_.file().GetPlatformFile(), fd);
    return -1;
  }

 protected:
  BurnWriter file_writer_;

  base::ScopedTempDir test_dir_;
  base::FilePath test_file_path_;
};

TEST_F(BurnReaderTest, ReadFile) {
  const std::string kTestFileContent = "test file content";
  ASSERT_TRUE(SetTestFileContent(kTestFileContent));

  ASSERT_TRUE(file_reader_.Open(test_file_path_.value().c_str()));

  EXPECT_EQ(kTestFileContent.size(), file_reader_.GetSize());

  ASSERT_LE(kTestFileContent.size(), kTestDataBufferSize);
  char kDataBuffer[kTestDataBufferSize] = {};
  const size_t kFirstReadSize = kTestFileContent.size() / 2;

  ASSERT_EQ(kFirstReadSize, file_reader_.Read(kDataBuffer, kFirstReadSize));
  EXPECT_EQ(kTestFileContent.substr(0, kFirstReadSize),
            std::string(kDataBuffer, kFirstReadSize));

  const size_t kExpectedSecondReadSize =
      kTestFileContent.size() - kFirstReadSize;
  ASSERT_EQ(kExpectedSecondReadSize,
            file_reader_.Read(kDataBuffer, kTestFileContent.size()));
  EXPECT_EQ(kTestFileContent.substr(kFirstReadSize),
            std::string(kDataBuffer, kExpectedSecondReadSize));

  EXPECT_EQ(0, file_reader_.Read(kDataBuffer, kTestFileContent.size()));

  EXPECT_TRUE(file_reader_.Close());
}

TEST_F(BurnReaderTest, ReopeningFile) {
  ASSERT_TRUE(file_reader_.Open(test_file_path_.value().c_str()));
  EXPECT_FALSE(file_reader_.Open(test_file_path_.value().c_str()));
  ASSERT_TRUE(file_reader_.Close());
}

TEST_F(BurnReaderTest, ReusingClosedReader) {
  const std::string kTestFileContent = "test file content";
  ASSERT_TRUE(SetTestFileContent(kTestFileContent));

  ASSERT_TRUE(file_reader_.Open(test_file_path_.value().c_str()));

  ASSERT_LE(kTestFileContent.size(), kTestDataBufferSize);
  char kDataBuffer[kTestDataBufferSize] = {};
  const size_t kFirstReadSize = kTestFileContent.size() / 2;

  ASSERT_EQ(kFirstReadSize, file_reader_.Read(kDataBuffer, kFirstReadSize));
  EXPECT_EQ(kTestFileContent.substr(0, kFirstReadSize),
            std::string(kDataBuffer, kFirstReadSize));

  ASSERT_TRUE(file_reader_.Close());

  ASSERT_TRUE(file_reader_.Open(test_file_path_.value().c_str()));
  ASSERT_EQ(kTestFileContent.size(),
            file_reader_.Read(kDataBuffer, kTestDataBufferSize));
  EXPECT_EQ(kTestFileContent,
            std::string(kDataBuffer, kTestFileContent.size()));

  ASSERT_TRUE(file_reader_.Close());
}

TEST_F(BurnReaderTest, HandlingEmptyFile) {
  ASSERT_TRUE(file_reader_.Open(test_file_path_.value().c_str()));

  EXPECT_EQ(0, file_reader_.GetSize());

  char kDataBuffer[kTestDataBufferSize] = {};
  EXPECT_EQ(0, file_reader_.Read(kDataBuffer, kTestDataBufferSize));

  ASSERT_TRUE(file_reader_.Close());
}

TEST_F(BurnReaderTest, HandlingNonExistingFile) {
  base::FilePath non_existent_file = test_dir_.GetPath().Append("non-existent");
  ASSERT_FALSE(base::PathExists(non_existent_file));

  EXPECT_FALSE(file_reader_.Open(non_existent_file.value().c_str()));
  EXPECT_EQ(-1, file_reader_.GetSize());
  EXPECT_FALSE(file_reader_.Close());
}

TEST_F(BurnWriterTest, WriteToNonBlockDevice) {
  EXPECT_FALSE(file_writer_.Open(test_file_path_.value().c_str()));
  EXPECT_FALSE(file_writer_.Close());
}

TEST_F(BurnWriterTest, FstatFailure) {
  file_writer_.set_fstat_for_test(base::BindRepeating(
      &BurnWriterTest::FailingFstat, base::Unretained(this)));
  EXPECT_FALSE(file_writer_.Open(test_file_path_.value().c_str()));
  EXPECT_FALSE(file_writer_.Close());
}

TEST_F(BurnWriterTest, WriteFile) {
  const std::string kTestFileContent = "test file content";
  file_writer_.set_fstat_for_test(base::BindRepeating(
      &BurnWriterTest::FakeBlockDeviceFstat, base::Unretained(this)));
  ASSERT_TRUE(file_writer_.Open(test_file_path_.value().c_str()));

  const size_t kFirstWriteSize = kTestFileContent.size() / 2;
  ASSERT_EQ(kFirstWriteSize,
            file_writer_.Write(kTestFileContent.data(), kFirstWriteSize));

  std::string file_content;
  ASSERT_TRUE(base::ReadFileToString(test_file_path_, &file_content));
  EXPECT_EQ(kTestFileContent.substr(0, kFirstWriteSize), file_content);

  const size_t kSecondWriteSize = kTestFileContent.size() - kFirstWriteSize;
  ASSERT_EQ(kSecondWriteSize,
            file_writer_.Write(kTestFileContent.data() + kFirstWriteSize,
                               kSecondWriteSize));

  ASSERT_TRUE(base::ReadFileToString(test_file_path_, &file_content));
  EXPECT_EQ(kTestFileContent, file_content);

  EXPECT_TRUE(file_writer_.Close());
}

TEST_F(BurnWriterTest, ReopeningFile) {
  file_writer_.set_fstat_for_test(base::BindRepeating(
      &BurnWriterTest::FakeBlockDeviceFstat, base::Unretained(this)));
  ASSERT_TRUE(file_writer_.Open(test_file_path_.value().c_str()));
  EXPECT_FALSE(file_writer_.Open(test_file_path_.value().c_str()));
  ASSERT_TRUE(file_writer_.Close());
}

TEST_F(BurnWriterTest, ReusingClosedReader) {
  const std::string kTestFileContent = "test file content";

  file_writer_.set_fstat_for_test(base::BindRepeating(
      &BurnWriterTest::FakeBlockDeviceFstat, base::Unretained(this)));
  ASSERT_TRUE(file_writer_.Open(test_file_path_.value().c_str()));

  const size_t kFirstWriteSize = kTestFileContent.size() / 2;
  ASSERT_EQ(kFirstWriteSize,
            file_writer_.Write(kTestFileContent.data(), kFirstWriteSize));

  std::string file_content;
  ASSERT_TRUE(base::ReadFileToString(test_file_path_, &file_content));
  EXPECT_EQ(kTestFileContent.substr(0, kFirstWriteSize), file_content);

  ASSERT_TRUE(file_writer_.Close());

  ASSERT_TRUE(file_writer_.Open(test_file_path_.value().c_str()));
  ASSERT_EQ(
      kTestFileContent.size(),
      file_writer_.Write(kTestFileContent.data(), kTestFileContent.size()));

  ASSERT_TRUE(base::ReadFileToString(test_file_path_, &file_content));
  EXPECT_EQ(kTestFileContent, file_content);

  ASSERT_TRUE(file_writer_.Close());
}

TEST_F(BurnWriterTest, HandlingNonExistingFile) {
  base::FilePath non_existent_file = test_dir_.GetPath().Append("non-existent");
  ASSERT_FALSE(base::PathExists(non_existent_file));

  file_writer_.set_fstat_for_test(base::BindRepeating(
      &BurnWriterTest::FakeBlockDeviceFstat, base::Unretained(this)));
  EXPECT_FALSE(file_writer_.Open(non_existent_file.value().c_str()));
  EXPECT_FALSE(file_writer_.Close());
}

}  // namespace imageburn
