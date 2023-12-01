// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_CHROMEOS_LEGACY_H_
#define INSTALLER_CHROMEOS_LEGACY_H_

#include <string>
#include <vector>

#include "installer/chromeos_install_config.h"

// Attempts to update boot files needed by the legacy bios boot
// (syslinux config files) on the boot partition. Returns false on error.
bool RunLegacyPostInstall(const InstallConfig& install_config);

// Attempts to update boot files needed by u-boot (not our secure u-boot)
// in some development situations.
bool RunLegacyUBootPostInstall(const InstallConfig& install_config);

// Attempts to update boot files needed by the EFI bios boot
// (grub config files) on the boot partition. Returns false on error.
bool RunEfiPostInstall(const InstallConfig& install_config);

// Valid boot slots for kernel command lines.
enum class BootSlot { A, B };

// Class to manipulate grub.cfg templates for updates.
class EfiGrubCfg {
 public:
  // Type of dm= option for a kernel command line being
  // selected.
  enum class DmOption {
    None,     // dm= option is missing from the cmdline
    Present,  // dm= option is present in the cmdline
  };

  EfiGrubCfg() = default;
  EfiGrubCfg(const EfiGrubCfg&) = delete;
  EfiGrubCfg& operator=(const EfiGrubCfg&) = delete;

  // Read the contents of the grub.cfg file at |path|.
  bool LoadFile(const base::FilePath& path);

  // String of the full grub.cfg file contents.
  std::string ToString() const;

  // Retrieves the full command line for the |slot| and |dm| argument.
  // With |dm| DmOption::Present it will return the line with a dm= argument.
  // With |dm| DmOption::None it will return the non-dm argument line.
  std::string GetKernelCommand(BootSlot slot, DmOption dm) const;

  // Replaces the full command lines for the |slot| with the given
  // command line.
  // With |dm| DmOption::Present will replace the dm= argument lines.
  // With |dm| DmOption::None it will replace the non-dm argument lines.
  // It is up to the caller to ensure the |cmd| to replace the entry
  // is valid.
  bool ReplaceKernelCommand(BootSlot slot, DmOption dm, std::string cmd);

  // Modifies the grub boot parameters as needed for the update.
  // Update all boot lines for the |slot| replacing PARTUUID and dm=
  // kernel arguments with the |root_uuid| and |verity_args| values.
  bool UpdateBootParameters(BootSlot slot,
                            const std::string& root_uuid,
                            const std::string& verity_args);

 private:
  std::vector<std::string> file_lines_;
};

#endif  // INSTALLER_CHROMEOS_LEGACY_H_
