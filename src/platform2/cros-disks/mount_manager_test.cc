// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for cros_disks::MountManager. See mount-manager.h for details
// on MountManager.

#include "cros-disks/mount_manager.h"

#include <sys/mount.h>
#include <sys/unistd.h>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/strings/strcat.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/metrics.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::IsEmpty;
using testing::Return;
using testing::SetArgPointee;
using testing::SizeIs;
using testing::StrictMock;

const char kMountRootDirectory[] = "/media/removable";
const char kSourcePath[] = "source";
const char kMountPath[] = "/media/removable/test";

}  // namespace

// A mock mount manager class for testing the mount manager base class.
class MountManagerUnderTest : public MountManager {
 public:
  MountManagerUnderTest(Platform* platform,
                        Metrics* metrics,
                        brillo::ProcessReaper* process_reaper)
      : MountManager(kMountRootDirectory, platform, metrics, process_reaper) {}

  ~MountManagerUnderTest() override { UnmountAll(); }

  MOCK_METHOD(bool, CanMount, (const std::string&), (const, override));
  MOCK_METHOD(MountSourceType, GetMountSourceType, (), (const, override));
  MOCK_METHOD(std::unique_ptr<MountPoint>,
              DoMount,
              (const std::string&,
               const std::string&,
               const std::vector<std::string>&,
               const base::FilePath&,
               MountError*),
              (override));
  MOCK_METHOD(bool,
              ShouldReserveMountPathOnError,
              (MountError),
              (const, override));
  MOCK_METHOD(std::string,
              SuggestMountPath,
              (const std::string&),
              (const, override));

  // Adds a mount point to the collection of mount points.
  void AddMount(std::unique_ptr<MountPoint> mount_point) {
    DCHECK(mount_point);
    DCHECK(!FindMountBySource(mount_point->source()));
    DCHECK(!FindMountByMountPath(mount_point->path()));
    mount_points_.push_back(std::move(mount_point));
  }

  bool IsMountPathInCache(const std::string& path) {
    return FindMountByMountPath(base::FilePath(path));
  }

  bool RemoveMountPathFromCache(const std::string& path) {
    MountPoint* mp = FindMountByMountPath(base::FilePath(path));
    if (!mp)
      return false;
    return RemoveMount(mp);
  }

  using MountManager::FindMountBySource;
};

class MountManagerTest : public ::testing::Test {
 public:
  MountManagerTest() : manager_(&platform_, &metrics_, &process_reaper_) {
    EXPECT_CALL(manager_, GetMountSourceType())
        .WillRepeatedly(Return(MOUNT_SOURCE_REMOVABLE_DEVICE));
    EXPECT_CALL(platform_, GetRealPath(_, _)).WillRepeatedly(Return(false));
  }

  std::unique_ptr<MountPoint> MakeMountPoint(const std::string& mount_path) {
    return MountPoint::CreateUnmounted(
        {.mount_path = base::FilePath(mount_path),
         .source = kSourcePath,
         .source_type = MOUNT_SOURCE_REMOVABLE_DEVICE},
        &platform_);
  }

  void OnMountCompleted(const std::string& fs_type,
                        const std::string& path,
                        const MountError error,
                        const bool read_only) {
    EXPECT_FALSE(mount_completed_);
    fs_type_ = fs_type;
    mount_path_ = path;
    mount_error_ = error;
    mount_completed_ = true;
    read_only_ = read_only;
  }

  MountManager::MountCallback GetMountCallback() {
    mount_path_.clear();
    mount_error_ = MountError::kSuccess;
    mount_completed_ = false;
    read_only_ = false;

    return base::BindOnce(&MountManagerTest::OnMountCompleted,
                          base::Unretained(this));
  }

 protected:
  Metrics metrics_;
  StrictMock<MockPlatform> platform_;
  brillo::ProcessReaper process_reaper_;
  StrictMock<MountManagerUnderTest> manager_;
  std::string filesystem_type_;
  std::string fs_type_;
  std::string mount_path_;
  MountError mount_error_;
  bool mount_completed_;
  bool read_only_;
  std::vector<std::string> options_;
};

// Verifies that MountManager::Initialize() returns false when it fails to
// create the mount root directory.
TEST_F(MountManagerTest, InitializeFailedInCreateDirectory) {
  EXPECT_CALL(platform_, CreateDirectory(kMountRootDirectory))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, SetOwnership(kMountRootDirectory, getuid(), getgid()))
      .Times(0);
  EXPECT_CALL(platform_, SetPermissions(kMountRootDirectory, _)).Times(0);
  EXPECT_CALL(platform_, CleanUpStaleMountPoints(_)).Times(0);

  EXPECT_FALSE(manager_.Initialize());
}

// Verifies that MountManager::Initialize() returns false when it fails to
// set the ownership of the created mount root directory.
TEST_F(MountManagerTest, InitializeFailedInSetOwnership) {
  EXPECT_CALL(platform_, CreateDirectory(kMountRootDirectory))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetOwnership(kMountRootDirectory, getuid(), getgid()))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, SetPermissions(kMountRootDirectory, _)).Times(0);
  EXPECT_CALL(platform_, CleanUpStaleMountPoints(_)).Times(0);

  EXPECT_FALSE(manager_.Initialize());
}

// Verifies that MountManager::Initialize() returns false when it fails to
// set the permissions of the created mount root directory.
TEST_F(MountManagerTest, InitializeFailedInSetPermissions) {
  EXPECT_CALL(platform_, CreateDirectory(kMountRootDirectory))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetOwnership(kMountRootDirectory, getuid(), getgid()))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetPermissions(kMountRootDirectory, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, CleanUpStaleMountPoints(_)).Times(0);

  EXPECT_FALSE(manager_.Initialize());
}

// Verifies that MountManager::Initialize() returns false when it fails to
// clean up stale mount points.
TEST_F(MountManagerTest, InitializeFailedInCleanUp) {
  EXPECT_CALL(platform_, CreateDirectory(kMountRootDirectory))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetOwnership(kMountRootDirectory, getuid(), getgid()))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetPermissions(kMountRootDirectory, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, CleanUpStaleMountPoints(kMountRootDirectory))
      .WillOnce(Return(false));

  EXPECT_FALSE(manager_.Initialize());
}

// Verifies that MountManager::Initialize() returns true when it creates
// the mount root directory with the specified ownership and permissions.
TEST_F(MountManagerTest, InitializeSucceeded) {
  EXPECT_CALL(platform_, CreateDirectory(kMountRootDirectory))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetOwnership(kMountRootDirectory, getuid(), getgid()))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SetPermissions(kMountRootDirectory, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, CleanUpStaleMountPoints(kMountRootDirectory))
      .WillOnce(Return(true));

  EXPECT_TRUE(manager_.Initialize());
}

// Verifies that MountManager::Mount() returns an error when it is invoked
// to mount an empty source path.
TEST_F(MountManagerTest, MountFailedWithEmptySourcePath) {
  EXPECT_CALL(manager_, SuggestMountPath(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  manager_.Mount("", filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kInvalidArgument, mount_error_);
  EXPECT_FALSE(read_only_);
}

// Verifies that MountManager::Mount() returns an error when it is invoked
// without a given mount path and the suggested mount path is invalid.
TEST_F(MountManagerTest, MountFailedWithInvalidSuggestedMountPath) {
  EXPECT_CALL(manager_, SuggestMountPath(_))
      .WillRepeatedly(Return("/media/removable/../test/doc"));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kInvalidPath, mount_error_);
  EXPECT_FALSE(read_only_);

  options_.push_back("mountlabel=custom_label");
  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kInvalidPath, mount_error_);
  EXPECT_FALSE(read_only_);
}

// Verifies that MountManager::Mount() returns an error when it is invoked
// with an mount label that yields an invalid mount path.
TEST_F(MountManagerTest, MountFailedWithInvalidMountLabel) {
  options_.push_back("mountlabel=../custom_label");

  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kSourcePath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kInvalidPath, mount_error_);
  EXPECT_FALSE(read_only_);
}

// Verifies that MountManager::Mount() returns an error when it fails to
// create the specified mount directory.
TEST_F(MountManagerTest, MountFailedInCreateOrReuseEmptyDirectory) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kDirectoryCreationFailed, mount_error_);
  EXPECT_EQ("", mount_path_);
  EXPECT_FALSE(read_only_);
}

// Verifies that MountManager::Mount() returns an error when it fails to
// create a mount directory after a number of trials.
TEST_F(MountManagerTest, MountFailedInCreateOrReuseEmptyDirectoryWithFallback) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kDirectoryCreationFailed, mount_error_);
  EXPECT_EQ("", mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_FALSE(manager_.IsMountPathInCache(kMountPath));
}

// Verifies that MountManager::Mount() fails when DoMount returns no MountPoint
// and no error (crbug.com/1317877 and crbug.com/1317878).
TEST_F(MountManagerTest, MountFailsWithNoMountPointAndNoError) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownError))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownError, mount_error_);
  EXPECT_EQ("", mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_FALSE(manager_.IsMountPathInCache(kMountPath));
}

// Verifies that MountManager::Mount() fails when DoMount returns both a
// MountPoint and an error.
TEST_F(MountManagerTest, MountFailsWithMountPointAndError) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kInvalidPath),
                      Return(ByMove(std::move(ptr)))));
  EXPECT_CALL(manager_, ShouldReserveMountPathOnError(MountError::kInvalidPath))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true))
      .WillOnce(Return(false));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kInvalidPath, mount_error_);
  EXPECT_EQ("", mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_FALSE(manager_.IsMountPathInCache(kMountPath));
}

// Verifies that MountManager::Mount() returns no error when it successfully
// mounts a source path in read-write mode.
TEST_F(MountManagerTest, MountSucceededWithGivenMountPath) {
  options_.push_back("rw");

  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  {
    const MountPoint* const mount_point =
        manager_.FindMountBySource(kSourcePath);
    ASSERT_TRUE(mount_point);
    EXPECT_FALSE(mount_point->is_read_only());
  }

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() stores correct mount status in cache when
// read-only option is specified.
TEST_F(MountManagerTest, MountCachesStatusWithReadOnlyOption) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  // Add read-only mount option.
  options_.push_back("ro");

  base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  {
    const MountPoint* const mount_point =
        manager_.FindMountBySource(kSourcePath);
    ASSERT_TRUE(mount_point);
    EXPECT_TRUE(mount_point->is_read_only());
  }

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
}

// Verifies that MountManager::Mount() stores correct mount status in cache when
// the mounter requested to mount in read-write mode but fell back to read-only
// mode.
TEST_F(MountManagerTest, MountSuccededWithReadOnlyFallback) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));
  options_.push_back("rw");
  // Emulate Mounter added read-only option as a fallback.
  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path, .flags = MS_RDONLY}, &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  {
    const MountPoint* const mount_point =
        manager_.FindMountBySource(kSourcePath);
    ASSERT_TRUE(mount_point);
    EXPECT_TRUE(mount_point->is_read_only());
  }

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
}

// Verifies that MountManager::Mount() returns no error when it successfully
// mounts a source path with no mount path specified.
TEST_F(MountManagerTest, MountSucceededWithEmptyMountPath) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() returns no error when it successfully
// mounts a source path with a given mount label in options.
TEST_F(MountManagerTest, MountSucceededWithGivenMountLabel) {
  const std::string final_mount_path =
      base::StrCat({kMountRootDirectory, "/custom_label"});
  options_.push_back("mountlabel=custom_label");
  std::vector<std::string> updated_options;

  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(final_mount_path);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, _, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(final_mount_path, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount(base::FilePath(final_mount_path), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(final_mount_path))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() handles the mounting of an already
// mounted source path properly.
TEST_F(MountManagerTest, MountWithAlreadyMountedSourcePath) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  // Mount an already-mounted source path
  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  // Mount an already-mounted source path
  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_FALSE(read_only_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  // Unmount
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(kMountPath));
}

// Verifies that MountManager::Mount() successfully reserves a path for a given
// type of error. A specific mount path is given in this case.
TEST_F(MountManagerTest, MountSucceededWithGivenMountPathInReservedCase) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() successfully reserves a path for a given
// type of error. No specific mount path is given in this case.
TEST_F(MountManagerTest, MountSucceededWithEmptyMountPathInReservedCase) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));

  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() successfully reserves a path for a given
// type of error and returns the same error when it tries to mount the same path
// again.
TEST_F(MountManagerTest, MountSucceededWithAlreadyReservedMountPath) {
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() successfully reserves a path for a given
// type of error and returns the same error when it tries to mount the same path
// again.
TEST_F(MountManagerTest, MountFailedWithGivenMountPathInReservedCase) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Mount() fails to mount or reserve a path for
// a type of error that is not enabled for reservation.
TEST_F(MountManagerTest, MountFailedWithEmptyMountPathInReservedCase) {
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, DoMount(kSourcePath, filesystem_type_, options_,
                                base::FilePath(kMountPath), _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(false));
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ("", mount_path_);
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Unmount() returns an error when it is invoked
// to unmount an empty path.
TEST_F(MountManagerTest, UnmountFailedWithEmptyPath) {
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);
  EXPECT_CALL(manager_, SuggestMountPath(_)).Times(0);

  EXPECT_EQ(MountError::kPathNotMounted, manager_.Unmount(mount_path_));
}

// Verifies that MountManager::Unmount() returns an error when it fails to
// unmount a path that is not mounted.
TEST_F(MountManagerTest, UnmountFailedWithPathNotMounted) {
  mount_path_ = "nonexistent-path";

  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectory(_)).Times(0);
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(_)).Times(0);
  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);
  EXPECT_CALL(manager_, SuggestMountPath(_)).Times(0);

  EXPECT_EQ(MountError::kPathNotMounted, manager_.Unmount(mount_path_));
}

// Verifies that MountManager::Unmount() returns no error when it successfully
// unmounts a source path.
TEST_F(MountManagerTest, UnmountSucceededWithGivenSourcePath) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);

  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, manager_.Unmount(kSourcePath));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Unmount() returns no error when it successfully
// unmounts a mount path.
TEST_F(MountManagerTest, UnmountSucceededWithGivenMountPath) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);

  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, manager_.Unmount(mount_path_));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Unmount() removes mount path from cache if
// it appears to be not mounted.
TEST_F(MountManagerTest, UnmountRemovesFromCacheIfNotMounted) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path,
                     .flags = IsReadOnlyMount(options_) ? MS_RDONLY : 0u},
      &platform_);

  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount(base::FilePath(mount_path_), ""))
      .WillOnce(Return(MountError::kPathNotMounted));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));

  EXPECT_EQ(MountError::kSuccess, manager_.Unmount(mount_path_));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Unmount() returns no error when it is invoked
// to unmount the source path of a reserved mount path.
TEST_F(MountManagerTest, UnmountSucceededWithGivenSourcePathInReservedCase) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount).Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, manager_.Unmount(kSourcePath));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::Unmount() returns no error when it is invoked
// to unmount a reserved mount path.
TEST_F(MountManagerTest, UnmountSucceededWithGivenMountPathInReservedCase) {
  EXPECT_CALL(manager_, SuggestMountPath(kSourcePath))
      .WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  const base::FilePath mount_path(kMountPath);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, options_, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kUnknownFilesystem),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(manager_,
              ShouldReserveMountPathOnError(MountError::kUnknownFilesystem))
      .WillOnce(Return(true));

  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, Unmount).Times(0);
  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, manager_.Unmount(mount_path_));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::IsMountPathInCache() works as expected.
TEST_F(MountManagerTest, IsMountPathInCache) {
  mount_path_ = kMountPath;

  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
  manager_.AddMount(MakeMountPoint(mount_path_));
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_TRUE(manager_.RemoveMountPathFromCache(mount_path_));
  EXPECT_FALSE(manager_.IsMountPathInCache(mount_path_));
}

// Verifies that MountManager::RemoveMountPathFromCache() works as expected.
TEST_F(MountManagerTest, RemoveMountPathFromCache) {
  mount_path_ = kMountPath;

  EXPECT_FALSE(manager_.RemoveMountPathFromCache(mount_path_));
  manager_.AddMount(MakeMountPoint(mount_path_));

  EXPECT_CALL(platform_, RemoveEmptyDirectory(mount_path_))
      .WillOnce(Return(true));
  EXPECT_TRUE(manager_.RemoveMountPathFromCache(mount_path_));
  EXPECT_FALSE(manager_.RemoveMountPathFromCache(mount_path_));
}

// Verifies that MountManager::GetMountPoints() returns the expected list of
// mount entries under different scenarios.
TEST_F(MountManagerTest, GetMountPoints) {
  // No mount entry is returned.
  EXPECT_THAT(manager_.GetMountPoints(), IsEmpty());

  // A normal mount entry is returned.
  manager_.AddMount(MakeMountPoint(kMountPath));
  const std::vector<const MountPoint*> mount_points = manager_.GetMountPoints();
  ASSERT_THAT(mount_points, SizeIs(1));
  EXPECT_EQ(MountError::kSuccess, mount_points[0]->error());
  EXPECT_EQ(kSourcePath, mount_points[0]->source());
  EXPECT_EQ(MOUNT_SOURCE_REMOVABLE_DEVICE, mount_points[0]->source_type());
  EXPECT_EQ(base::FilePath(kMountPath), mount_points[0]->path());

  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
}

// Verifies that MountManager::IsPathImmediateChildOfParent() correctly
// determines if a path is an immediate child of another path.
TEST_F(MountManagerTest, IsPathImmediateChildOfParent) {
  EXPECT_TRUE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip"),
      base::FilePath("/media/archive")));
  EXPECT_TRUE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip/"),
      base::FilePath("/media/archive")));
  EXPECT_TRUE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip"),
      base::FilePath("/media/archive/")));
  EXPECT_TRUE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip/"),
      base::FilePath("/media/archive/")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip/doc.zip"),
      base::FilePath("/media/archive/")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/archive/test.zip"),
      base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/tmp/archive/test.zip"),
      base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media"), base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/removable"), base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/removable/"), base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/removable/."),
      base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsPathImmediateChildOfParent(
      base::FilePath("/media/removable/.."),
      base::FilePath("/media/removable")));
}

// Verifies that MountManager::IsValidMountPath() correctly determines if a
// mount path is an immediate child of the mount root.
TEST_F(MountManagerTest, IsValidMountPath) {
  EXPECT_TRUE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test")));
  EXPECT_TRUE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test/")));
  EXPECT_TRUE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test/")));
  EXPECT_TRUE(
      manager_.IsValidMountPath(base::FilePath("/media/removable//test")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/archive/test")));
  EXPECT_FALSE(manager_.IsValidMountPath(base::FilePath("/media/removable")));
  EXPECT_FALSE(manager_.IsValidMountPath(base::FilePath("/media/removable/")));
  EXPECT_FALSE(manager_.IsValidMountPath(base::FilePath("/media/removable/.")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/..")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test/doc")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/../test")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/../test/")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test/..")));
  EXPECT_FALSE(
      manager_.IsValidMountPath(base::FilePath("/media/removable/test/../")));
}

// Verifies that MountManager::Mount() returns an error when the source is
// not mounted yet but attempted to remount it.
TEST_F(MountManagerTest, RemountFailedNotMounted) {
  options_.push_back("remount");

  EXPECT_CALL(manager_, DoMount(_, _, _, _, _)).Times(0);

  // source = kSourcePath has not been mounted yet.
  manager_.Mount(kSourcePath, filesystem_type_, options_, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kPathNotMounted, mount_error_);
}

// Verifies that MountManager::Mount() returns no error when it successfully
// remounts a source path on a specified mount path.
TEST_F(MountManagerTest, RemountSucceededWithGivenSourcePath) {
  // Mount a device in read-write mode.
  base::FilePath mount_path(kMountPath);
  EXPECT_CALL(manager_, SuggestMountPath(_)).WillOnce(Return(kMountPath));
  EXPECT_CALL(platform_, CreateOrReuseEmptyDirectoryWithFallback(_, _, _))
      .WillOnce(Return(true));

  auto ptr = std::make_unique<MountPoint>(
      MountPointData{.mount_path = mount_path, .flags = 0}, &platform_);
  EXPECT_CALL(manager_,
              DoMount(kSourcePath, filesystem_type_, _, mount_path, _))
      .WillOnce(DoAll(SetArgPointee<4>(MountError::kSuccess),
                      Return(ByMove(std::move(ptr)))));
  manager_.Mount(kSourcePath, filesystem_type_, {"rw"}, GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);

  {
    const MountPoint* const mount_point =
        manager_.FindMountBySource(kSourcePath);
    ASSERT_TRUE(mount_point);
    EXPECT_FALSE(mount_point->is_read_only());
    EXPECT_EQ(base::FilePath(kMountPath), mount_point->path());
  }

  // Remount with read-only mount option.
  EXPECT_CALL(platform_, Mount(kSourcePath, kMountPath, filesystem_type_,
                               MS_RDONLY | MS_REMOUNT, _))
      .WillOnce(Return(MountError::kSuccess));
  manager_.Mount(kSourcePath, filesystem_type_, {"remount", "ro"},
                 GetMountCallback());
  EXPECT_TRUE(mount_completed_);
  EXPECT_EQ(MountError::kSuccess, mount_error_);
  EXPECT_EQ(kMountPath, mount_path_);
  EXPECT_TRUE(manager_.IsMountPathInCache(mount_path_));

  {
    const MountPoint* const mount_point =
        manager_.FindMountBySource(kSourcePath);
    ASSERT_TRUE(mount_point);
    EXPECT_TRUE(mount_point->is_read_only());
  }

  // Should be unmounted correctly even after remount.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountPath), ""))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountPath))
      .WillOnce(Return(true));
  manager_.UnmountAll();
  EXPECT_FALSE(manager_.IsMountPathInCache(kMountPath));
}

}  // namespace cros_disks
