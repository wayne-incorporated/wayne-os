// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_SLOW_BOOT_NOTIFY_H_
#define INSTALLER_SLOW_BOOT_NOTIFY_H_

#include <base/files/file_path.h>

// Functions invoked by chromeos_postinst to extract the FSPM before and
// after the firmware update. The FSPM extracted will then be compared to
// decide if slow boot is required/enabled.
void SlowBootNotifyPreFwUpdate(const base::FilePath& fspm_main);
void SlowBootNotifyPostFwUpdate(const base::FilePath& fspm_next);

// In case of firmware update, return true if slow boot notification has to be
// generated, else return false.
bool SlowBootNotifyRequired(const base::FilePath& fspm_main,
                            const base::FilePath& fspm_next);

#endif  // INSTALLER_SLOW_BOOT_NOTIFY_H_
