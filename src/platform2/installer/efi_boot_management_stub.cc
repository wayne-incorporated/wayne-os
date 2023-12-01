// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/efi_boot_management.h"

// No-op. Always return true.
bool UpdateEfiBootEntries(const InstallConfig& install_config) {
  return true;
}
