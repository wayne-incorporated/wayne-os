// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_UEFI_STARTUP_IMPL_H_
#define INIT_STARTUP_UEFI_STARTUP_IMPL_H_

#include <string>

#include <base/files/file_path.h>

#include "init/startup/platform_impl.h"
#include "init/startup/uefi_startup.h"

namespace startup {

// Path of the system efi directory (relative to the root dir). This
// directory will only exist when booting from UEFI firmware.
constexpr char kSysEfiDir[] = "sys/firmware/efi";

// Mount point for efivarfs (relative to the root dir). This directory
// is used to read and write UEFI variables.
constexpr char kEfivarsDir[] = "sys/firmware/efi/efivars";

// Mount point for EFI System Partition (relative to the root dir).
constexpr char kEspDir[] = "efi";

// Label of the EFI System Partition.
constexpr char kEspLabel[] = "EFI-SYSTEM";

// File system name used for mounting efivarfs.
constexpr char kFsTypeEfivarfs[] = "efivarfs";

// File system name used for mounting the EFI System Partition.
constexpr char kFsTypeVfat[] = "vfat";

// Vendor GUID used for the dbx UEFI variable. This is defined in the
// UEFI Specification under the "Device Signature Database Update" section.
constexpr char kEfiImageSecurityDatabaseGuid[] =
    "d719b2cb-3d3a-4596-a3bc-dad00e67656f";

class UefiDelegateImpl : public UefiDelegate {
 public:
  UefiDelegateImpl(Platform& platform, const base::FilePath& root_dir);

  bool IsUefiEnabled() const override;
  std::optional<UserAndGroup> GetFwupdUserAndGroup() const override;
  bool MountEfivarfs() override;
  bool MakeUefiVarWritableByFwupd(const std::string& vendor,
                                  const std::string& name,
                                  const UserAndGroup& fwupd) override;
  bool MountEfiSystemPartition(const UserAndGroup& fwupd) override;

 private:
  Platform& platform_;
  const base::FilePath root_dir_;
};

}  // namespace startup

#endif  // INIT_STARTUP_UEFI_STARTUP_IMPL_H_
