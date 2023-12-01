// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "dlcservice/boot/mock_boot_slot.h"
#include "dlcservice/metrics.h"
#include "dlcservice/prefs.h"
#include "dlcservice/system_state.h"
#include "dlcservice/test_utils.h"
#include "dlcservice/utils.h"

using dlcservice::metrics::InstallResult;
using testing::_;
using testing::DoAll;
using testing::ElementsAre;
using testing::Return;
using testing::SetArgPointee;

namespace dlcservice {

class DlcBaseTest : public BaseTest {
 public:
  DlcBaseTest() = default;

  DlcBaseTest(const DlcBaseTest&) = delete;
  DlcBaseTest& operator=(const DlcBaseTest&) = delete;

  std::unique_ptr<DlcBase> Install(const DlcId& id) {
    auto dlc = std::make_unique<DlcBase>(id);
    dlc->Initialize();
    EXPECT_CALL(*mock_update_engine_proxy_ptr_, SetDlcActiveValue(_, id, _, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
    EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
    EXPECT_CALL(*mock_metrics_,
                SendInstallResult(InstallResult::kSuccessNewInstall));
    EXPECT_TRUE(dlc->Install(&err_));
    InstallWithUpdateEngine({id});
    dlc->InstallCompleted(&err_);
    dlc->FinishInstall(/*installed_by_ue=*/true, &err_);
    return dlc;
  }

  void SetUp() override {
    ON_CALL(*mock_boot_slot_ptr_, GetSlot())
        .WillByDefault(Return(BootSlotInterface::Slot::A));
    ON_CALL(*mock_boot_slot_ptr_, IsDeviceRemovable())
        .WillByDefault(Return(false));
    BaseTest::SetUp();
  }
};

class DlcBaseTestRemovable : public DlcBaseTest {
 public:
  DlcBaseTestRemovable() = default;

  DlcBaseTestRemovable(const DlcBaseTestRemovable&) = delete;
  DlcBaseTestRemovable& operator=(const DlcBaseTestRemovable&) = delete;

  void SetUp() override {
    DlcBaseTest::SetUp();
    ON_CALL(*mock_boot_slot_ptr_, IsDeviceRemovable())
        .WillByDefault(Return(true));
  }
};

TEST_F(DlcBaseTest, InitializationClearsMountFile) {
  Prefs prefs(
      JoinPaths(SystemState::Get()->dlc_prefs_dir(), kFirstDlc, kPackage));
  EXPECT_TRUE(prefs.Create(kDlcRootMount));
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  EXPECT_FALSE(prefs.Exists(kDlcRootMount));
}

TEST_F(DlcBaseTest, InitializationReservedSpace) {
  // First DLC has `reserved` set to true.
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  EXPECT_TRUE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->active_boot_slot())));
  EXPECT_TRUE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot())));
}

TEST_F(DlcBaseTest, InitializationReservedSpaceOmitted) {
  // Second DLC has `reserved` set to false/missing.
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->active_boot_slot())));
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot())));
}

TEST_F(DlcBaseTestRemovable, InitializationReservedSpaceOnRemovableDevice) {
  // First DLC has `reserved` set to true.
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->active_boot_slot())));
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot())));
}

TEST_F(DlcBaseTest, InitializationReservedSpaceDoesNotSparsifyAgain) {
  // First DLC has `reserved` set to true.
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  auto* system_state = SystemState::Get();
  auto a_img = dlc.GetImagePath(system_state->active_boot_slot());
  auto b_img = dlc.GetImagePath(system_state->inactive_boot_slot());
  auto a_img_size = GetFileSize(a_img);
  auto b_img_size = GetFileSize(b_img);

  EXPECT_TRUE(base::PathExists(a_img));
  EXPECT_TRUE(base::PathExists(b_img));
  EXPECT_TRUE(WriteToFile(a_img, std::string(a_img_size, '1')));
  EXPECT_TRUE(WriteToFile(b_img, std::string(b_img_size, '2')));

  std::vector<uint8_t> expected_hash_a, expected_hash_b;
  EXPECT_TRUE(HashFile(a_img, a_img_size, &expected_hash_a));
  EXPECT_TRUE(HashFile(b_img, b_img_size, &expected_hash_b));

  // Mimic a reboot.
  dlc.Initialize();

  // On reboot, there should not be resizing + re-sparsing of images.
  std::vector<uint8_t> actual_hash_a, actual_hash_b;
  EXPECT_TRUE(HashFile(a_img, a_img_size, &actual_hash_a));
  EXPECT_TRUE(HashFile(b_img, b_img_size, &actual_hash_b));

  EXPECT_EQ(expected_hash_a, actual_hash_a);
  EXPECT_EQ(expected_hash_b, actual_hash_b);
}

TEST_F(DlcBaseTest, ReinstallingNonReservedSpaceDoesNotSparsifyAgain) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_TRUE(dlc.Install(&err_));

  auto* system_state = SystemState::Get();
  auto a_img = dlc.GetImagePath(system_state->active_boot_slot());
  auto b_img = dlc.GetImagePath(system_state->inactive_boot_slot());
  auto a_img_size = GetFileSize(a_img);
  auto b_img_size = GetFileSize(b_img);

  EXPECT_TRUE(base::PathExists(a_img));
  EXPECT_TRUE(base::PathExists(b_img));
  EXPECT_TRUE(WriteToFile(a_img, std::string(a_img_size, '2')));
  EXPECT_TRUE(WriteToFile(b_img, std::string(b_img_size, '3')));

  std::vector<uint8_t> expected_hash_a, expected_hash_b;
  EXPECT_TRUE(HashFile(a_img, a_img_size, &expected_hash_a));
  EXPECT_TRUE(HashFile(b_img, b_img_size, &expected_hash_b));

  // Mimic re-install after reboot.
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  dlc.ChangeState(DlcState::NOT_INSTALLED);
  EXPECT_TRUE(dlc.Install(&err_));

  // There should not be resizing + re-sparsing of images.
  std::vector<uint8_t> actual_hash_a, actual_hash_b;
  EXPECT_TRUE(HashFile(a_img, a_img_size, &actual_hash_a));
  EXPECT_TRUE(HashFile(b_img, b_img_size, &actual_hash_b));

  EXPECT_EQ(expected_hash_a, actual_hash_a);
  EXPECT_EQ(expected_hash_b, actual_hash_b);
}

TEST_F(DlcBaseTest, CreateDlc) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);

  EXPECT_TRUE(dlc.Install(&err_));

  constexpr int expected_permissions = 0755;
  int permissions;
  base::FilePath module_path = JoinPaths(content_path_, kFirstDlc, kPackage);
  base::GetPosixFilePermissions(module_path, &permissions);
  EXPECT_EQ(permissions, expected_permissions);
  base::FilePath image_a_path =
      GetDlcImagePath(content_path_, kFirstDlc, kPackage, BootSlot::Slot::A);
  base::GetPosixFilePermissions(image_a_path.DirName(), &permissions);
  EXPECT_EQ(permissions, expected_permissions);
  base::FilePath image_b_path =
      GetDlcImagePath(content_path_, kFirstDlc, kPackage, BootSlot::Slot::B);
  base::GetPosixFilePermissions(image_b_path.DirName(), &permissions);
  EXPECT_EQ(permissions, expected_permissions);

  base::FilePath dlc_prefs_path = JoinPaths(prefs_path_, "dlc", kFirstDlc);
  EXPECT_TRUE(base::PathExists(dlc_prefs_path));
  base::GetPosixFilePermissions(dlc_prefs_path, &permissions);
  EXPECT_EQ(permissions, expected_permissions);

  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);
}

TEST_F(DlcBaseTest, InstallWithUECompletion) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessNewInstall));

  EXPECT_TRUE(dlc.Install(&err_));
  InstallWithUpdateEngine({kFirstDlc});
  // UE calls this.
  dlc.InstallCompleted(&err_);
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);

  dlc.FinishInstall(/*installed_by_ue=*/true, &err_);
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLED);
  EXPECT_TRUE(dlc.IsVerified());
}

TEST_F(DlcBaseTest, InstallWithoutUECompletion) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessNewInstall));

  EXPECT_TRUE(dlc.Install(&err_));
  InstallWithUpdateEngine({kFirstDlc});
  // UE doesn't call InstallComplete anymore. But we still verify.
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);

  dlc.FinishInstall(/*installed_by_ue=*/true, &err_);
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLED);
  EXPECT_TRUE(dlc.IsVerified());
}

TEST_F(DlcBaseTest, InstallWhenInstalling) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);

  // A second install should do nothing.
  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);
}

TEST_F(DlcBaseTest, VerifiedOnInitialization) {
  DlcBase dlc(kSecondDlc);

  // Explicitly set |kDlcPrefVerified| here.
  std::string value;
  EXPECT_TRUE(
      base::ReadFileToString(SystemState::Get()->verification_file(), &value));
  EXPECT_TRUE(Prefs(dlc, SystemState::Get()->active_boot_slot())
                  .SetKey(kDlcPrefVerified, value));
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);

  dlc.Initialize();
  EXPECT_TRUE(dlc.IsVerified());
}

TEST_F(DlcBaseTest, StaleVerificationCheckOnInitialization) {
  DlcBase dlc(kSecondDlc);

  // Explicitly set |kDlcPrefVerified| here w/ stale value.
  std::string value;
  EXPECT_TRUE(
      base::ReadFileToString(SystemState::Get()->verification_file(), &value));
  EXPECT_TRUE(Prefs(dlc, SystemState::Get()->active_boot_slot())
                  .SetKey(kDlcPrefVerified, value + "make it stale"));
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);

  dlc.Initialize();
  EXPECT_FALSE(dlc.IsVerified());
}

TEST_F(DlcBaseTest, InstallCompleted) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_FALSE(dlc.IsVerified());
  EXPECT_TRUE(dlc.InstallCompleted(&err_));
  EXPECT_TRUE(dlc.IsVerified());
}

TEST_F(DlcBaseTest, UpdateCompleted) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_TRUE(dlc.UpdateCompleted(&err_));
  EXPECT_TRUE(Prefs(dlc, SystemState::Get()->inactive_boot_slot())
                  .Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, MakeReadyForUpdate) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();
  dlc.MarkVerified();
  // Make sure the function recreates the inactive image.
  auto inactive_image_path =
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot());
  base::DeleteFile(inactive_image_path);
  EXPECT_FALSE(base::PathExists(inactive_image_path));

  Prefs prefs(dlc, SystemState::Get()->inactive_boot_slot());
  EXPECT_TRUE(prefs.Create(kDlcPrefVerified));
  EXPECT_TRUE(dlc.MakeReadyForUpdate());
  EXPECT_TRUE(base::PathExists(inactive_image_path));
  EXPECT_FALSE(prefs.Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, MakeReadyForUpdateNotVerfied) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  Prefs prefs(dlc, SystemState::Get()->inactive_boot_slot());
  EXPECT_TRUE(prefs.Create(kDlcPrefVerified));
  // Since DLC is not verfied, it should return false.
  EXPECT_FALSE(dlc.MakeReadyForUpdate());
  EXPECT_FALSE(prefs.Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, MakeReadyForUpdateSkipScaledDlc) {
  DlcBase dlc(kScaledDlc);
  dlc.Initialize();

  Prefs prefs(dlc, SystemState::Get()->inactive_boot_slot());
  EXPECT_TRUE(prefs.Create(kDlcPrefVerified));
  // Since DLC is scaled, it should return false.
  EXPECT_FALSE(dlc.MakeReadyForUpdate());
  EXPECT_FALSE(prefs.Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, OfficialBuildsDoNotPreloadDLCs) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  // Place preloaded images.
  base::FilePath image_path = SetUpDlcPreloadedImage(kThirdDlc);

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(true));

  EXPECT_TRUE(dlc.Install(&err_));

  // Instead of being preloaded, it should start installing.
  EXPECT_TRUE(dlc.IsInstalling());
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, BootingFromNonRemovableDeviceKeepsPreloadedDLCs) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  // Place preloaded images.
  base::FilePath image_path = SetUpDlcPreloadedImage(kThirdDlc);

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(false));

  EXPECT_TRUE(dlc.Install(&err_));

  // Preloaded DLC image should still exists.
  EXPECT_TRUE(base::PathExists(image_path));
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTestRemovable, BootingFromRemovableDeviceKeepsPreloadedDLCs) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  // Place preloaded images.
  base::FilePath image_path = SetUpDlcPreloadedImage(kThirdDlc);

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(false));

  EXPECT_TRUE(dlc.Install(&err_));

  // Preloaded DLC image should still exists.
  EXPECT_TRUE(base::PathExists(image_path));
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, PreloadCopyShouldMarkUnverified) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  SetUpDlcPreloadedImage(kThirdDlc);

  // Don't preload the image so we can simulate a preload failure.
  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_FALSE(dlc.PreloadedCopier(&err_));
  EXPECT_FALSE(dlc.IsVerified());
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, PreloadCopyFailOnInvalidFileSize) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  base::FilePath image_path = SetUpDlcPreloadedImage(kThirdDlc);
  EXPECT_TRUE(ResizeFile(image_path, 10));

  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_FALSE(dlc.PreloadedCopier(&err_));
  // This failure should not render the image as unverified.
  EXPECT_TRUE(dlc.IsVerified());
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, InstallingCorruptPreloadedImageCleansUp) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  base::FilePath image_path = SetUpDlcPreloadedImage(kThirdDlc);
  EXPECT_TRUE(ResizeFile(image_path, 10));

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(false));

  EXPECT_FALSE(dlc.Install(&err_));
  for (const auto& path : {dlc.GetImagePath(BootSlot::Slot::A),
                           dlc.GetImagePath(BootSlot::Slot::B)})
    EXPECT_FALSE(base::PathExists(path));
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, PreloadingSkippedOnAlreadyVerifiedDlc) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();

  // Cause |PreloadedCopier()| to fail due to size mismatch in manifest if it
  // were to be called.
  EXPECT_TRUE(ResizeFile(SetUpDlcPreloadedImage(kThirdDlc), 1));
  SetUpDlcWithSlots(kThirdDlc);
  InstallWithUpdateEngine({kThirdDlc});

  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kThirdDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());
}

// TODO(crbug.com/1042704): Deprecate after DLCs are provisioned using TLS API.
TEST_F(DlcBaseTest, PreloadingSkippedOnAlreadyExistingAndVerifiableDlc) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();

  // Cause |PreloadedCopier()| to fail due to size mismatch in manifest if it
  // were to be called.
  EXPECT_TRUE(ResizeFile(SetUpDlcPreloadedImage(kThirdDlc), 1));
  SetUpDlcWithSlots(kThirdDlc);
  InstallWithUpdateEngine({kThirdDlc});

  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kThirdDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());
}

TEST_F(DlcBaseTest, FactoryInstalledImagesSupportedIntialization) {
  base::FilePath factory_image_path = SetUpDlcFactoryImage(kThirdDlc);
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  EXPECT_TRUE(base::PathExists(factory_image_path));
}

TEST_F(DlcBaseTest, FactoryInstalledImagesUnsupportedIntialization) {
  base::FilePath unsupported_factory_image_path =
      SetUpDlcFactoryImage(kFirstDlc);
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  EXPECT_FALSE(base::PathExists(unsupported_factory_image_path));
}

TEST_F(DlcBaseTest, FactoryInstalledImageClearsAfterInstallation) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  base::FilePath factory_image_path = SetUpDlcFactoryImage(kThirdDlc);
  EXPECT_TRUE(base::PathExists(factory_image_path));

  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kThirdDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());
  EXPECT_FALSE(base::PathExists(factory_image_path));
}

TEST_F(DlcBaseTest, FactoryInstalledImageSizeCorruption) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  base::FilePath factory_image_path = SetUpDlcFactoryImage(kThirdDlc);
  EXPECT_TRUE(ResizeFile(factory_image_path, 1));

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(true));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalling());
  EXPECT_FALSE(base::PathExists(factory_image_path));
}

TEST_F(DlcBaseTest, FactoryInstalledImageDataCorruption) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  base::FilePath factory_image_path = SetUpDlcFactoryImage(kThirdDlc);
  EXPECT_TRUE(WriteToFile(factory_image_path, "foobar"));

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_CALL(*mock_system_properties_, IsOfficialBuild())
      .WillOnce(Return(true));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalling());
  EXPECT_FALSE(base::PathExists(factory_image_path));
}

TEST_F(DlcBaseTest, HasContent) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_FALSE(dlc.HasContent());

  SetUpDlcWithSlots(kSecondDlc);
  EXPECT_TRUE(dlc.HasContent());
}

TEST_F(DlcBaseTest, GetUsedBytesOnDisk) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_EQ(dlc.GetUsedBytesOnDisk(), 0);

  SetUpDlcWithSlots(kSecondDlc);
  uint64_t expected_size = 0;
  for (const auto& path : {dlc.GetImagePath(BootSlot::Slot::A),
                           dlc.GetImagePath(BootSlot::Slot::B)}) {
    expected_size += GetFileSize(path);
  }
  EXPECT_GT(expected_size, 0);

  EXPECT_EQ(dlc.GetUsedBytesOnDisk(), expected_size);
}

TEST_F(DlcBaseTest, MarkVerified) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_FALSE(dlc.IsVerified());
  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_TRUE(dlc.IsVerified());
  EXPECT_TRUE(Prefs(DlcBase(kFirstDlc), SystemState::Get()->active_boot_slot())
                  .Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, MarkUnverified) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_TRUE(dlc.MarkUnverified());
  EXPECT_FALSE(dlc.IsVerified());
  EXPECT_FALSE(Prefs(DlcBase(kFirstDlc), SystemState::Get()->active_boot_slot())
                   .Exists(kDlcPrefVerified));
}

TEST_F(DlcBaseTest, ImageOnDiskButNotVerifiedInstalls) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  SetUpDlcWithSlots(kSecondDlc);
  InstallWithUpdateEngine({kSecondDlc});

  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kSecondDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kSecondDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());
}

TEST_F(DlcBaseTest, ImageOnDiskVerifiedInstalls) {
  DlcBase dlc(kSecondDlc);
  EXPECT_TRUE(Prefs(dlc, SystemState::Get()->active_boot_slot())
                  .Create(kDlcPrefVerified));
  SetUpDlcWithSlots(kSecondDlc);
  InstallWithUpdateEngine({kSecondDlc});

  dlc.Initialize();

  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kSecondDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kSecondDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());
}

TEST_F(DlcBaseTest, VerifyDlcImageOnUEFailureToCompleteInstall) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kSecondDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kSecondDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessNewInstall));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalling());

  // Intentionally skip over setting verified mark before |FinishInstall()|.
  InstallWithUpdateEngine({kSecondDlc});

  EXPECT_TRUE(dlc.FinishInstall(/*installed_by_ue=*/true, &err_));
  EXPECT_TRUE(dlc.IsInstalled());
}

TEST_F(DlcBaseTest, NoImageFoundOnUEFailureToDownloadDlc) {
  DlcBase dlc(kSecondDlc);
  dlc.Initialize();

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kFailedNoImageFound));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalling());

  // Make sure the `last_attempt_error` in update_engine is set to `kNoUpdate`.
  update_engine::StatusResult ue_status;
  ue_status.set_last_attempt_error(
      static_cast<int32_t>(update_engine::ErrorCode::kNoUpdate));
  SystemState::Get()->set_update_engine_status(ue_status);

  EXPECT_FALSE(dlc.FinishInstall(/*installed_by_ue=*/true, &err_));
}

TEST_F(DlcBaseTest, DefaultState) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.mount_point_ = base::FilePath("foo-path");

  DlcState state = dlc.GetState();
  EXPECT_EQ(state.id(), kFirstDlc);
  EXPECT_EQ(state.state(), DlcState::NOT_INSTALLED);
  EXPECT_EQ(state.progress(), 0);
  EXPECT_EQ(state.root_path(), "");
}

TEST_F(DlcBaseTest, ChangeStateNotInstalled) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.mount_point_ = base::FilePath("foo-path");

  EXPECT_CALL(
      mock_state_change_reporter_,
      DlcStateChanged(CheckDlcStateProto(DlcState::NOT_INSTALLED, 0, "")));
  dlc.ChangeState(DlcState::NOT_INSTALLED);
}

TEST_F(DlcBaseTest, ChangeStateInstalling) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.mount_point_ = base::FilePath("foo-path");

  EXPECT_CALL(mock_state_change_reporter_,
              DlcStateChanged(CheckDlcStateProto(DlcState::INSTALLING, 0, "")));
  dlc.ChangeState(DlcState::INSTALLING);
}

TEST_F(DlcBaseTest, ChangeStateInstalled) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.mount_point_ = base::FilePath("foo-path");

  // The |root_path| in |DlcState| should point to the root of the mount point.
  EXPECT_CALL(mock_state_change_reporter_,
              DlcStateChanged(CheckDlcStateProto(DlcState::INSTALLED, 1.0,
                                                 "foo-path/root")));
  dlc.ChangeState(DlcState::INSTALLED);
}

TEST_F(DlcBaseTest, ChangeProgress) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();

  // Any state other than installing should not change the progress.
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(0);
  dlc.ChangeProgress(0.5);

  EXPECT_CALL(mock_state_change_reporter_,
              DlcStateChanged(CheckDlcStateProto(DlcState::INSTALLING, 0, "")));
  dlc.ChangeState(DlcState::INSTALLING);

  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(CheckDlcStateProto(
                                               DlcState::INSTALLING, 0.5, "")));
  dlc.ChangeProgress(0.5);

  // Lower progress should not send signal.
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(0);
  dlc.ChangeProgress(0.3);

  // Same progress should not send the signal.
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(0);
  dlc.ChangeProgress(0.5);
}

TEST_F(DlcBaseTest, MountFileCreated) {
  // |kFirstDlc| has 'mount-file-required' as true in the manifest.
  DlcBase dlc(kFirstDlc);
  SetUpDlcWithSlots(kFirstDlc);
  InstallWithUpdateEngine({kFirstDlc});
  dlc.Initialize();

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(
      Prefs(JoinPaths(SystemState::Get()->dlc_prefs_dir(), kFirstDlc, kPackage))
          .Exists(kDlcRootMount));
}

TEST_F(DlcBaseTest, MountFileNotCreated) {
  // |kSecondDlc| has 'mount-file-required' as false in the manifest.
  DlcBase dlc(kSecondDlc);
  SetUpDlcWithSlots(kSecondDlc);
  InstallWithUpdateEngine({kSecondDlc});
  dlc.Initialize();

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kSecondDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_FALSE(Prefs(JoinPaths(SystemState::Get()->dlc_prefs_dir(), kSecondDlc,
                               kPackage))
                   .Exists(kDlcRootMount));
}

TEST_F(DlcBaseTest, MountFileRequiredDeletionOnUninstall) {
  DlcBase dlc(kFirstDlc);
  SetUpDlcWithSlots(kFirstDlc);
  InstallWithUpdateEngine({kFirstDlc});
  dlc.Initialize();

  // Process |Install()|.
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, LoadDlcImage(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));
  EXPECT_TRUE(dlc.Install(&err_));

  // Process |Uninstall()| + check.
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, UnloadDlcImage(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
  EXPECT_TRUE(dlc.Uninstall(&err_));
  EXPECT_FALSE(
      Prefs(JoinPaths(SystemState::Get()->dlc_prefs_dir(), kFirstDlc, kPackage))
          .Exists(kDlcRootMount));
}

TEST_F(DlcBaseTest, UnmountClearsMountPoint) {
  auto dlc = Install(kFirstDlc);

  EXPECT_CALL(*mock_image_loader_proxy_ptr_, UnloadDlcImage(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
  EXPECT_TRUE(dlc->Unmount(&err_));
  EXPECT_TRUE(dlc->GetRoot().empty());
}

TEST_F(DlcBaseTest, ReserveInstall) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.SetReserve(true);

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kFailedNoImageFound));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);

  update_engine::StatusResult ue_status;
  ue_status.set_last_attempt_error(
      static_cast<int32_t>(update_engine::ErrorCode::kNoUpdate));
  SystemState::Get()->set_update_engine_status(ue_status);

  dlc.FinishInstall(/*installed_by_ue=*/true, &err_);
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);

  // DLC images should be reserved.
  EXPECT_TRUE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->active_boot_slot())));
  EXPECT_TRUE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot())));
}

TEST_F(DlcBaseTest, UnReservedInstall) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.SetReserve(false);

  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kFailedNoImageFound));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_EQ(dlc.GetState().state(), DlcState::INSTALLING);

  update_engine::StatusResult ue_status;
  ue_status.set_last_attempt_error(
      static_cast<int32_t>(update_engine::ErrorCode::kNoUpdate));
  SystemState::Get()->set_update_engine_status(ue_status);

  dlc.FinishInstall(/*installed_by_ue=*/true, &err_);
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);

  // DLC images should not be reserved.
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->active_boot_slot())));
  EXPECT_FALSE(base::PathExists(
      dlc.GetImagePath(SystemState::Get()->inactive_boot_slot())));
}

TEST_F(DlcBaseTest, ReserveValueClearsAfterUninstall) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  dlc.SetReserve(true);

  // Uninstall the DLC.
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kFirstDlc, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(1);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_, UnloadDlcImage(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
  EXPECT_TRUE(dlc.Uninstall(&err_));

  EXPECT_FALSE(dlc.SetReserve(std::nullopt));
}

TEST_F(DlcBaseTest, ScaledOff) {
  DlcBase dlc(kFirstDlc);
  dlc.Initialize();
  EXPECT_FALSE(dlc.IsScaled());
}

TEST_F(DlcBaseTest, ScaledOn) {
  DlcBase dlc(kScaledDlc);
  dlc.Initialize();
  EXPECT_TRUE(dlc.IsScaled());
}

TEST_F(DlcBaseTest, IsInstalledButUnmounted) {
  DlcBase dlc(kThirdDlc);
  dlc.Initialize();
  SetUpDlcWithSlots(kThirdDlc);
  InstallWithUpdateEngine({kThirdDlc});

  EXPECT_TRUE(dlc.MarkVerified());
  EXPECT_EQ(dlc.GetState().state(), DlcState::NOT_INSTALLED);
  EXPECT_CALL(*mock_image_loader_proxy_ptr_,
              LoadDlcImage(kThirdDlc, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mount_path_.value()), Return(true)));
  EXPECT_CALL(*mock_update_engine_proxy_ptr_,
              SetDlcActiveValue(_, kThirdDlc, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_state_change_reporter_, DlcStateChanged(_)).Times(2);
  EXPECT_CALL(*mock_metrics_,
              SendInstallResult(InstallResult::kSuccessAlreadyInstalled));

  EXPECT_TRUE(dlc.Install(&err_));
  EXPECT_TRUE(dlc.IsInstalled());

  // Fake unmount.
  ASSERT_TRUE(base::DeletePathRecursively(dlc.GetRoot()));
  EXPECT_FALSE(dlc.IsInstalled());
}

}  // namespace dlcservice
