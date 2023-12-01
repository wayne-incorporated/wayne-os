// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_UEFI_STARTUP_H_
#define INIT_STARTUP_UEFI_STARTUP_H_

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "init/startup/platform_impl.h"

namespace startup {

// Abstract class for UEFI operations.
class UefiDelegate {
 public:
  // User and group ID.
  struct UserAndGroup {
    uid_t uid;
    gid_t gid;
  };

  // Create a concrete instance of the default implementation.
  static std::unique_ptr<UefiDelegate> Create(Platform& platform,
                                              const base::FilePath& root_dir);

  virtual ~UefiDelegate();

  // Check if the device was booted from UEFI firmware. This is done by
  // checking if "/sys/firmware/efi" exists.
  virtual bool IsUefiEnabled() const = 0;

  // Get the user ID and group ID for fwupd.
  virtual std::optional<UserAndGroup> GetFwupdUserAndGroup() const = 0;

  // Mount the filesystem that provides access to UEFI
  // variables. Returns true on success.
  virtual bool MountEfivarfs() = 0;

  // Make a UEFI variable writable by the fwupd service. This applies
  // two changes to the variable:
  //
  // 1. The file's attributes are modified to remove the immutable
  //    bit. That bit is set by the kernel to make it harder for end
  //    users to accidentally brick a machine by deleting UEFI
  //    variables. Some firmware is poorly implemented and will do
  //    unexpected things if variables it expects go missing. We need to
  //    relax this restriction for UEFI variables that fwupd will
  //    modify.
  // 2. The file's owner and group are changed to fwupd.
  //
  // Returns true on success.
  virtual bool MakeUefiVarWritableByFwupd(const std::string& vendor,
                                          const std::string& name,
                                          const UserAndGroup& fwupd) = 0;

  // Mount the EFI System Partition (ESP).
  //
  // The ESP is mounted at /efi. This is a FAT filesystem, so it doesn't
  // have unix permissions. The files need to be writable by fwupd, so
  // mount options are used to set the user and group of all files to
  // fwupd.
  //
  // Returns true on success.
  virtual bool MountEfiSystemPartition(const UserAndGroup& fwupd) = 0;
};

// Initialize directories needed for UEFI platforms. Does nothing if not
// booted from UEFI firmware.
//
// Errors are logged, but not propagated to the caller.
void MaybeRunUefiStartup(UefiDelegate& uefi_delegate);

}  // namespace startup

#endif  // INIT_STARTUP_UEFI_STARTUP_H_
