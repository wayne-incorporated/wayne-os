// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_DEBUGD_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_DEBUGD_CONSTANTS_H_

namespace diagnostics {

inline constexpr char kNvmeShortSelfTestOption[] = "short_self_test";
inline constexpr char kNvmeLongSelfTestOption[] = "long_self_test";
inline constexpr char kNvmeStopSelfTestOption[] = "stop_self_test";
inline constexpr char kNvmeIdentityOption[] = "identify_controller";
inline constexpr char kMmcExtcsdReadOption[] = "extcsd_read";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_DEBUGD_CONSTANTS_H_
