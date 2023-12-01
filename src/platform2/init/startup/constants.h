// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_CONSTANTS_H_
#define INIT_STARTUP_CONSTANTS_H_

#include <sys/mount.h>

namespace startup {

// These constants are used to check the clock. Since they need to be
// updated, which can be done by a script in BUILD.gn, they are in a
// separate file for ease of maintenance.
constexpr int kYear = 2023;
// This isn't exactly correct as it doesn't handle leap years, but it's
// good enough for our purposes (pulling clock to the ~last year).
constexpr uint64_t kBaseSecs = (kYear - 1970) * (365 * 24 * 60 * 60);

// Many of the mount calls in chromeos_startup utilize these flags.
// Making this a constant to simplify those mount calls, but this
// should only be used in cases where these specific mount flags are
// needed.
constexpr int kCommonMountFlags = MS_NOSUID | MS_NODEV | MS_NOEXEC;

// TPM Owned path, used to determine whether the TPM is owned.
constexpr char kTPMOwnedPath[] = "sys/class/tpm/tpm0/device/owned";

}  // namespace startup

#endif  // INIT_STARTUP_CONSTANTS_H_
