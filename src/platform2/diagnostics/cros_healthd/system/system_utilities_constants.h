// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_CONSTANTS_H_

namespace diagnostics {

// Machines populated by uname().
inline constexpr char kUnameMachineX86_64[] = "x86_64";
inline constexpr char kUnameMachineAArch64[] = "aarch64";
inline constexpr char kUnameMachineArmv7l[] = "armv7l";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_CONSTANTS_H_
