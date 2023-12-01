// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_CONSTANTS_H_

namespace diagnostics {

inline constexpr char kDelegateMojoChannelHandle[] =
    "delegate-mojo-channel-handle";

namespace path {

inline constexpr char kProcUptime[] = "/proc/uptime";
inline constexpr char kBiosTimes[] = "/var/log/bios_times.txt";
inline constexpr char kShutdownMetrics[] = "/var/log/metrics";
inline constexpr char kPreviousPowerdLog[] =
    "/var/log/power_manager/powerd.PREVIOUS";
inline constexpr char kUptimeLoginPromptVisible[] =
    "/tmp/uptime-login-prompt-visible";

// The path to the fingerprint device node.
inline constexpr char kCrosFpDevice[] = "/dev/cros_fp";

}  // namespace path

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_CONSTANTS_H_
