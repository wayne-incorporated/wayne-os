// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_NAMES_H_
#define DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_NAMES_H_

namespace cros_minidiag {

namespace metrics {
// General metrics
inline constexpr char kLaunchHistogram[] = "Platform.MiniDiag.Launch";
inline constexpr char kOpenDurationHistogram[] =
    "Platform.MiniDiag.OpenDuration";

// Max of metrics
inline constexpr int kLaunchCountMax = 50;
inline constexpr int kOpenDurationMin = 0;
inline constexpr int kOpenDurationMax = 3600;
inline constexpr int kOpenDurationBucket = 50;

// Test-specific metrics
inline constexpr char kMemoryCheckFull[] = "Platform.MiniDiag.MemoryCheckFull.";
inline constexpr char kMemoryCheckQuick[] =
    "Platform.MiniDiag.MemoryCheckQuick.";
inline constexpr char kStorageHealthInfo[] =
    "Platform.MiniDiag.StorageHealthInfo.";
inline constexpr char kStorageSelfTestExtended[] =
    "Platform.MiniDiag.StorageSelfTestExtended.";
inline constexpr char kStorageSelfTestShort[] =
    "Platform.MiniDiag.StorageSelfTestShort.";

inline constexpr char kSuffixOpenDuration[] = "OpenDuration";
inline constexpr char kSuffixResult[] = "Result";

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class MiniDiagResultType {
  kPassed = 0,
  kError = 1,
  kFailed = 2,
  kAborted = 3,
  kMaxValue = kAborted,
};

}  // namespace metrics
}  // namespace cros_minidiag

#endif  // DIAGNOSTICS_CROS_MINIDIAG_MINIDIAG_METRICS_NAMES_H_
