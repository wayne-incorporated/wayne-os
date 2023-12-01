// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/mount_point.h"

#include <limits>
#include <utility>

#include <base/test/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/mock_platform.h"
#include "cros-disks/platform.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::ElementsAre;
using testing::Return;
using testing::StrictMock;

class MountPointTest : public testing::Test {
 protected:
  const std::string kMountPath = "/mount/path";
  const std::string kSource = "source";
  const std::string kFSType = "fstype";
  const std::string kOptions = "foo=bar";
  StrictMock<MockPlatform> platform_;
  const MountPointData data_ = {.mount_path = base::FilePath(kMountPath),
                                .source = kSource,
                                .filesystem_type = kFSType,
                                .flags = MS_DIRSYNC | MS_NODEV,
                                .data = kOptions};
};

}  // namespace

TEST_F(MountPointTest, Unmount) {
  auto mount_point = std::make_unique<MountPoint>(data_, &platform_);

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kBusy));
  EXPECT_EQ(MountError::kBusy, mount_point->Unmount());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, mount_point->Unmount());

  EXPECT_EQ(MountError::kPathNotMounted, mount_point->Unmount());
}

TEST_F(MountPointTest, UnmountOnDestroy) {
  const std::unique_ptr<MountPoint> mount_point =
      std::make_unique<MountPoint>(data_, &platform_);
  EXPECT_TRUE(mount_point->is_mounted());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(false));
}

TEST_F(MountPointTest, UnmountError) {
  const std::unique_ptr<MountPoint> mount_point =
      std::make_unique<MountPoint>(data_, &platform_);
  EXPECT_TRUE(mount_point->is_mounted());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kPathNotMounted));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kPathNotMounted, mount_point->Unmount());

  EXPECT_FALSE(mount_point->is_mounted());
}

TEST_F(MountPointTest, Remount) {
  const std::unique_ptr<MountPoint> mount_point =
      std::make_unique<MountPoint>(data_, &platform_);
  EXPECT_TRUE(mount_point->is_mounted());
  EXPECT_FALSE(mount_point->is_read_only());

  EXPECT_CALL(platform_,
              Mount(kSource, kMountPath, kFSType,
                    MS_DIRSYNC | MS_NODEV | MS_RDONLY | MS_REMOUNT, kOptions))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_EQ(MountError::kSuccess, mount_point->Remount(true));
  EXPECT_TRUE(mount_point->is_read_only());

  EXPECT_CALL(platform_, Mount(kSource, kMountPath, kFSType,
                               MS_DIRSYNC | MS_NODEV | MS_REMOUNT, kOptions))
      .WillOnce(Return(MountError::kInternalError));
  EXPECT_EQ(MountError::kInternalError, mount_point->Remount(false));
  EXPECT_TRUE(mount_point->is_read_only());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
}

TEST_F(MountPointTest, RemountUnmounted) {
  const std::unique_ptr<MountPoint> mount_point =
      MountPoint::CreateUnmounted(data_);
  EXPECT_FALSE(mount_point->is_mounted());
  EXPECT_FALSE(mount_point->is_read_only());

  EXPECT_EQ(MountError::kPathNotMounted, mount_point->Remount(true));
  EXPECT_FALSE(mount_point->is_read_only());
}

TEST_F(MountPointTest, MountError) {
  EXPECT_CALL(platform_, Mount(kSource, kMountPath, kFSType,
                               MS_DIRSYNC | MS_NODEV, kOptions))
      .WillOnce(Return(MountError::kInvalidArgument));

  MountError error = MountError::kUnknownError;
  const std::unique_ptr<MountPoint> mount_point =
      MountPoint::Mount(data_, &platform_, &error);
  EXPECT_FALSE(mount_point);
  EXPECT_EQ(MountError::kInvalidArgument, error);
}

TEST_F(MountPointTest, MountSucceeds) {
  MountError error = MountError::kUnknownError;
  EXPECT_CALL(platform_, Mount(kSource, kMountPath, kFSType,
                               MS_DIRSYNC | MS_NODEV, kOptions))
      .WillOnce(Return(MountError::kSuccess));

  const std::unique_ptr<MountPoint> mount_point =
      MountPoint::Mount(data_, &platform_, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  EXPECT_TRUE(mount_point);
  EXPECT_TRUE(mount_point->is_mounted());
  EXPECT_EQ(data_.mount_path, mount_point->path());
  EXPECT_EQ(data_.source, mount_point->source());
  EXPECT_EQ(data_.filesystem_type, mount_point->fstype());
  EXPECT_EQ(data_.flags, mount_point->flags());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), kFSType))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
}

TEST_F(MountPointTest, CreateUnmounted) {
  const std::unique_ptr<MountPoint> mount_point =
      MountPoint::CreateUnmounted(data_);
  EXPECT_TRUE(mount_point);
  EXPECT_FALSE(mount_point->is_mounted());
  EXPECT_EQ(data_.mount_path, mount_point->path());
  EXPECT_EQ(data_.source, mount_point->source());
  EXPECT_EQ(data_.filesystem_type, mount_point->fstype());
  EXPECT_EQ(data_.flags, mount_point->flags());
}

TEST_F(MountPointTest, ParseProgressMessage) {
  int percent = -1;
  EXPECT_FALSE(MountPoint::ParseProgressMessage("", &percent));
  EXPECT_FALSE(MountPoint::ParseProgressMessage("x", &percent));
  EXPECT_EQ(percent, -1);

  EXPECT_FALSE(MountPoint::ParseProgressMessage("%", &percent));
  EXPECT_FALSE(MountPoint::ParseProgressMessage(" %", &percent));
  EXPECT_FALSE(MountPoint::ParseProgressMessage("x%", &percent));

  percent = -1;
  EXPECT_TRUE(MountPoint::ParseProgressMessage("0%", &percent));
  EXPECT_EQ(percent, 0);

  percent = -1;
  EXPECT_TRUE(MountPoint::ParseProgressMessage("Whatever 1%", &percent));
  EXPECT_EQ(percent, 1);

  percent = -1;
  EXPECT_TRUE(MountPoint::ParseProgressMessage("Whatever 99%", &percent));
  EXPECT_EQ(percent, 99);

  percent = -1;
  EXPECT_TRUE(MountPoint::ParseProgressMessage("Whatever 100%", &percent));
  EXPECT_EQ(percent, 100);

  percent = -1;
  EXPECT_FALSE(MountPoint::ParseProgressMessage("Whatever 101%", &percent));
  EXPECT_EQ(percent, 101);

  percent = -1;
  EXPECT_FALSE(MountPoint::ParseProgressMessage("Whatever 9999999999999999999%",
                                                &percent));
  EXPECT_EQ(percent, std::numeric_limits<int>::max());
}

TEST_F(MountPointTest, ProgressCallback) {
  const std::unique_ptr<MountPoint> mount_point =
      MountPoint::CreateUnmounted(data_);
  mount_point->OnProgress("Loading 1%");
  mount_point->OnProgress("Loading 2%");
  std::vector<int> progress_percents;
  mount_point->SetProgressCallback(base::BindLambdaForTesting(
      [&progress_percents, want_mount_point = mount_point.get()](
          const MountPoint* const got_mount_point) {
        EXPECT_EQ(want_mount_point, got_mount_point);
        progress_percents.push_back(got_mount_point->progress_percent());
      }));
  mount_point->OnProgress("Loading 3%");
  mount_point->OnProgress("Loading 99%");
  mount_point->OnProgress("");
  mount_point->OnProgress("%");
  mount_point->OnProgress("xx%");
  mount_point->OnProgress("Ignored 1");
  mount_point->OnProgress("Loading 100%");
  EXPECT_THAT(progress_percents, ElementsAre(3, 99, 100));
}

}  // namespace cros_disks
