// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/namespaces/mock_platform.h>
#include <gtest/gtest.h>

#include "minios/logger.h"
#include "minios/mock_disk_util.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

namespace minios {

class LoggerTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(root_path_.CreateUniqueTempDir());
    auto mock_disk_util = std::make_unique<StrictMock<MockDiskUtil>>();
    mock_disk_util_ptr_ = mock_disk_util.get();
    auto mock_platform = std::make_unique<StrictMock<brillo::MockPlatform>>();
    mock_platform_ptr_ = mock_platform.get();
    logger_ = std::make_unique<Logger>(std::move(mock_disk_util),
                                       std::move(mock_platform),
                                       root_path_.GetPath());
  }

 protected:
  base::ScopedTempDir root_path_;

  MockDiskUtil* mock_disk_util_ptr_;
  brillo::MockPlatform* mock_platform_ptr_;
  std::unique_ptr<Logger> logger_;
};

TEST_F(LoggerTest, DumpLogsIntoStatefulNoDriveExists) {
  EXPECT_CALL(*mock_disk_util_ptr_, GetFixedDrive())
      .WillOnce(Return(base::FilePath()));
  EXPECT_FALSE(logger_->DumpLogsIntoStateful());
}

TEST_F(LoggerTest, DumpLogsIntoStatefulNoStatefulExists) {
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  const base::FilePath drive = tmp_dir.GetPath();

  EXPECT_CALL(*mock_disk_util_ptr_, GetFixedDrive()).WillOnce(Return(drive));
  EXPECT_CALL(*mock_disk_util_ptr_, GetStatefulPartition(_))
      .WillOnce(Return(base::FilePath()));
  EXPECT_FALSE(logger_->DumpLogsIntoStateful());
}

TEST_F(LoggerTest, DumpLogIntoStatefulMountFailure) {
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  const base::FilePath drive = tmp_dir.GetPath();

  EXPECT_CALL(*mock_disk_util_ptr_, GetFixedDrive()).WillOnce(Return(drive));
  EXPECT_CALL(*mock_disk_util_ptr_, GetStatefulPartition(_))
      .WillOnce(Return(drive));
  EXPECT_CALL(*mock_platform_ptr_, Mount(_, _, _, _, _)).WillOnce(Return(-1));
  EXPECT_FALSE(logger_->DumpLogsIntoStateful());
}

TEST_F(LoggerTest, DumpLogIntoStatefulUnmountFailureIsSuccess) {
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  const base::FilePath drive = tmp_dir.GetPath();

  EXPECT_CALL(*mock_disk_util_ptr_, GetFixedDrive()).WillOnce(Return(drive));
  EXPECT_CALL(*mock_disk_util_ptr_, GetStatefulPartition(_))
      .WillOnce(Return(drive));
  EXPECT_CALL(*mock_platform_ptr_, Mount(_, _, _, _, _)).WillOnce(Return(0));
  EXPECT_CALL(*mock_platform_ptr_, Unmount(_, _, _)).WillOnce(Return(false));
  // Failing to unmount is still successful.
  EXPECT_TRUE(logger_->DumpLogsIntoStateful());
}

TEST_F(LoggerTest, DumpLogIntoStatefulSuccess) {
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  const base::FilePath drive = tmp_dir.GetPath();

  // Create sample log files.
  const base::FilePath kLogName("some-log-file");
  ASSERT_TRUE(
      base::WriteFile(root_path_.GetPath().Append(kLogName), "some-logging"));

  EXPECT_CALL(*mock_disk_util_ptr_, GetFixedDrive()).WillOnce(Return(drive));
  EXPECT_CALL(*mock_disk_util_ptr_, GetStatefulPartition(_))
      .WillOnce(Return(drive));
  EXPECT_CALL(*mock_platform_ptr_, Mount(_, _, _, _, _)).WillOnce(Return(0));
  EXPECT_CALL(*mock_platform_ptr_, Unmount(_, _, _)).WillOnce(Return(true));
  EXPECT_TRUE(logger_->DumpLogsIntoStateful());

  // Check that logs are copied.
  EXPECT_TRUE(
      base::PathExists(logger_->GetMountPath().Append(kMiniOSLogsDirectory)));
  EXPECT_TRUE(base::PathExists(logger_->GetMountPath()
                                   .Append(kMiniOSLogsDirectory)
                                   .Append(root_path_.GetPath().BaseName())
                                   .Append(kLogName)));
}

}  // namespace minios
