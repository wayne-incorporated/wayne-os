// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DLC_BASE_H_
#define DLCSERVICE_DLC_BASE_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/errors/error.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <libimageloader/manifest.h>
#include <chromeos/dbus/service_constants.h>

#include "dlcservice/boot/boot_slot.h"
#include "dlcservice/dlc_interface.h"
#include "dlcservice/types.h"

namespace dlcservice {

// TODO(kimjae): Make `DlcBase` a true base class by only holding and
// implementation truly common methods.
class DlcBase : public DlcInterface {
 public:
  explicit DlcBase(DlcId id) : id_(std::move(id)) {}
  virtual ~DlcBase() = default;

  DlcBase(const DlcBase&) = delete;
  DlcBase& operator=(const DlcBase&) = delete;

  bool Initialize() override;
  const DlcId& GetId() const override;
  const std::string& GetName() const override;
  const std::string& GetDescription() const override;
  DlcState GetState() const override;
  base::FilePath GetRoot() const override;
  bool IsInstalling() const override;
  bool IsInstalled() const override;
  bool IsVerified() const override;
  bool IsScaled() const override;
  bool HasContent() const override;
  uint64_t GetUsedBytesOnDisk() const override;
  bool IsPreloadAllowed() const override;
  bool IsFactoryInstall() const override;
  bool Install(brillo::ErrorPtr* err) override;
  bool FinishInstall(bool installed_by_ue, brillo::ErrorPtr* err) override;
  bool CancelInstall(const brillo::ErrorPtr& err_in,
                     brillo::ErrorPtr* err) override;
  bool Uninstall(brillo::ErrorPtr* err) override;
  bool InstallCompleted(brillo::ErrorPtr* err) override;
  bool UpdateCompleted(brillo::ErrorPtr* err) override;
  bool MakeReadyForUpdate() const override;
  void ChangeProgress(double progress) override;
  bool SetReserve(std::optional<bool> reserve) override;

 protected:
  friend class DBusServiceTest;
  FRIEND_TEST(DlcBaseTest, InitializationReservedSpace);
  FRIEND_TEST(DlcBaseTest, InitializationReservedSpaceOmitted);
  FRIEND_TEST(DlcBaseTestRemovable,
              InitializationReservedSpaceOnRemovableDevice);
  FRIEND_TEST(DlcBaseTest, InitializationReservedSpaceDoesNotSparsifyAgain);
  FRIEND_TEST(DlcBaseTest, ReinstallingNonReservedSpaceDoesNotSparsifyAgain);
  FRIEND_TEST(DBusServiceTest, GetInstalled);
  FRIEND_TEST(DlcBaseTest, GetUsedBytesOnDisk);
  FRIEND_TEST(DlcBaseTest, DefaultState);
  FRIEND_TEST(DlcBaseTest, ChangeStateNotInstalled);
  FRIEND_TEST(DlcBaseTest, ChangeStateInstalling);
  FRIEND_TEST(DlcBaseTest, ChangeStateInstalled);
  FRIEND_TEST(DlcBaseTest, ChangeProgress);
  FRIEND_TEST(DlcBaseTest, MakeReadyForUpdate);
  FRIEND_TEST(DlcBaseTest, MarkUnverified);
  FRIEND_TEST(DlcBaseTest, MarkVerified);
  FRIEND_TEST(DlcBaseTest, PreloadCopyShouldMarkUnverified);
  FRIEND_TEST(DlcBaseTest, PreloadCopyFailOnInvalidFileSize);
  FRIEND_TEST(DlcBaseTest, InstallingCorruptPreloadedImageCleansUp);
  FRIEND_TEST(DlcBaseTest, PreloadingSkippedOnAlreadyVerifiedDlc);
  FRIEND_TEST(DlcBaseTest, UnmountClearsMountPoint);
  FRIEND_TEST(DlcBaseTest, ReserveInstall);
  FRIEND_TEST(DlcBaseTest, UnReservedInstall);
  FRIEND_TEST(DlcBaseTest, IsInstalledButUnmounted);

  virtual bool MakeReadyForUpdateInternal() const;

  // Returns the path to the DLC image given the slot.
  virtual base::FilePath GetImagePath(BootSlot::Slot slot) const;

  // Creates the DLC directories and files if they don't exist. This function
  // should be used as fall-through. We should call this even if we presumably
  // know the files are already there. This allows us to create any new DLC
  // files that didn't exist on a previous version of the DLC.
  virtual bool CreateDlc(brillo::ErrorPtr* err);

  // Mark the current active DLC image as verified.
  bool MarkVerified();

  // Mark the current active DLC image as unverified.
  bool MarkUnverified();

  // Returns true if the DLC image in the current active slot matches the hash
  // of that in the rootfs manifest for the DLC.
  bool Verify();
  virtual bool VerifyInternal(const base::FilePath& image_path,
                              std::vector<uint8_t>* image_sha256);

  // Helper used to load in (copy + cleanup) preloadable files for the DLC.
  bool PreloadedCopier(brillo::ErrorPtr* err);

  // Helper used to load in (copy + cleanup) factory installed DLC.
  bool FactoryInstallCopier();

  // Mounts the DLC image.
  bool Mount(brillo::ErrorPtr* err);
  virtual bool MountInternal(std::string* mount_point, brillo::ErrorPtr* err);

  // Unmounts the DLC image.
  bool Unmount(brillo::ErrorPtr* err);

  // Returns true if the active DLC image is present.
  bool IsActiveImagePresent() const;

  // Deletes DLC and performs related cleanups.
  bool Delete(brillo::ErrorPtr* err);

  // Deletes all directories related to this DLC.
  virtual bool DeleteInternal(brillo::ErrorPtr* err);

  // Changes the state of the current DLC. It also notifies the state change
  // reporter that a state change has been made.
  void ChangeState(DlcState::State state);

  // Sets the DLC as being active or not based on |active| value.
  void SetActiveValue(bool active);

  DlcId id_;
  std::string package_;

  // The verification value which validates the current verification stamps is
  // valid.
  std::string verification_value_;

  DlcState state_;

  base::FilePath mount_point_;

  std::shared_ptr<imageloader::Manifest> manifest_;

  // Indicator to keep DLC in cache even if installation fails.
  bool reserve_ = false;

  // The directories on the stateful partition where the DLC image will reside.
  base::FilePath content_id_path_;
  base::FilePath content_package_path_;
  base::FilePath prefs_path_;
  base::FilePath prefs_package_path_;
  base::FilePath preloaded_image_path_;
  base::FilePath factory_install_image_path_;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DLC_BASE_H_
