// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_EFI_BOOT_MANAGEMENT_H_
#define INSTALLER_EFI_BOOT_MANAGEMENT_H_

#include <memory>

#include "installer/chromeos_install_config.h"
#include "installer/metrics.h"

// On systems with CrOS-managed EFI boot entries: tries to ensure a single
// EFI boot entry exists. Returns false for failures that can interfere with
// future booting, true otherwise.
// On other systems: no-op. Always returns true.
bool UpdateEfiBootEntries(const InstallConfig& install_config);

#endif  // INSTALLER_EFI_BOOT_MANAGEMENT_H_
