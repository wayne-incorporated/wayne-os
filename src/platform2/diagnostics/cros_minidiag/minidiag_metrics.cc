// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <string>

#include <base/containers/fixed_flat_map.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>

#include "diagnostics/cros_minidiag/minidiag_metrics.h"
#include "diagnostics/cros_minidiag/minidiag_metrics_names.h"

namespace cros_minidiag {

namespace {

// The type names that showed in elogtool output.
// Some of the type names changed their cases, so we have to cast into lower
// case before looking up.
inline constexpr char kTypeNameMemoryCheckFull[] = "memory check (full)";
inline constexpr char kTypeNameMemoryCheckQuick[] = "memory check (quick)";
inline constexpr char kTypeNameStorageHealthInfo[] = "storage health info";
inline constexpr char kTypeNameStorageSelfTestExtended[] =
    "storage self-test (extended)";
inline constexpr char kTypeNameStorageSelfTestShort[] =
    "storage self-test (short)";

// The result names that showed in elogtool output.
inline constexpr char kResultPassed[] = "passed";
inline constexpr char kResultError[] = "error";
inline constexpr char kResultFailed[] = "failed";
inline constexpr char kResultAborted[] = "aborted";

// IMPORTANT: To obsolete a metric enum value, just remove it from the map
// initialization and comment it out on the Enum.
constexpr auto kTypeNames =
    base::MakeFixedFlatMap<base::StringPiece, base::StringPiece>({
        {kTypeNameMemoryCheckFull, metrics::kMemoryCheckFull},
        {kTypeNameMemoryCheckQuick, metrics::kMemoryCheckQuick},
        {kTypeNameStorageHealthInfo, metrics::kStorageHealthInfo},
        {kTypeNameStorageSelfTestExtended, metrics::kStorageSelfTestExtended},
        {kTypeNameStorageSelfTestShort, metrics::kStorageSelfTestShort},
    });

constexpr auto kResultNames =
    base::MakeFixedFlatMap<base::StringPiece, metrics::MiniDiagResultType>({
        {kResultPassed, metrics::MiniDiagResultType::kPassed},
        {kResultError, metrics::MiniDiagResultType::kError},
        {kResultFailed, metrics::MiniDiagResultType::kFailed},
        {kResultAborted, metrics::MiniDiagResultType::kAborted},
    });

// Since we need to cast the duration (in seconds) to int before sending to
// the metrics library, we need to set its hard limit to INT_MAX.
// Note that this is not the `max` under `SendToUMA`. By the metrics guide, it
// is still allowed to send some data exceeds the `max`; but any data exceeds
// INT_MAX will cause the metrics library reports unexpected data, which is
// invalid.
constexpr base::TimeDelta kTimeLimit =
    base::Seconds(std::numeric_limits<int>::max());

}  // namespace

MiniDiagMetrics::MiniDiagMetrics() = default;
MiniDiagMetrics::~MiniDiagMetrics() = default;

void MiniDiagMetrics::RecordLaunch(int count) const {
  if (!metrics_library_->SendLinearToUMA(metrics::kLaunchHistogram, count,
                                         metrics::kLaunchCountMax))
    LOG(ERROR) << "Cannot send MiniDiag launch count to UMA";
}

void MiniDiagMetrics::RecordTestReport(const std::string& type,
                                       const std::string& result,
                                       const base::TimeDelta& time) const {
  auto it_type = kTypeNames.find(base::StringPiece(base::ToLowerASCII(type)));
  auto it_result =
      kResultNames.find(base::StringPiece(base::ToLowerASCII(result)));
  if (it_type == kTypeNames.end()) {
    LOG(ERROR) << "Type name not exist: " << type;
    return;
  }
  if (it_result == kResultNames.end()) {
    LOG(ERROR) << "Result not exist: " << result;
    return;
  }
  if (!IsTimeValid(time)) {
    LOG(ERROR) << "Open duration not valid: " << time.InSeconds();
    return;
  }
  const std::string& metrics_prefix{it_type->second};
  const metrics::MiniDiagResultType& result_code = it_result->second;
  // Send Platform.MiniDiag.[Type].Result metrics.
  if (!metrics_library_->SendEnumToUMA(
          metrics_prefix + metrics::kSuffixResult,
          static_cast<int>(result_code),
          static_cast<int>(metrics::MiniDiagResultType::kMaxValue))) {
    LOG(ERROR) << "Cannot send MiniDiag test result to UMA";
  }
  // Send Platform.MiniDiag.[Type].OpenDuration metrics.
  if (!metrics_library_->SendToUMA(
          metrics_prefix + metrics::kSuffixOpenDuration,
          static_cast<int>(time.InSeconds()), metrics::kOpenDurationMin,
          metrics::kOpenDurationMax, metrics::kOpenDurationBucket)) {
    LOG(ERROR) << "Cannot send MiniDiag test open duration to UMA";
  }
}

void MiniDiagMetrics::RecordOpenDuration(const base::TimeDelta& time) const {
  if (!IsTimeValid(time)) {
    LOG(ERROR) << "Open duration not valid: " << time.InSeconds();
    return;
  }
  // Send Platform.MiniDiag.OpenDuration metrics.
  if (!metrics_library_->SendToUMA(
          metrics::kOpenDurationHistogram, static_cast<int>(time.InSeconds()),
          metrics::kOpenDurationMin, metrics::kOpenDurationMax,
          metrics::kOpenDurationBucket)) {
    LOG(ERROR) << "Cannot send MiniDiag open duration to UMA";
  }
}

bool MiniDiagMetrics::IsTimeValid(const base::TimeDelta& time) const {
  return (!time.is_negative()) && (time <= kTimeLimit);
}

}  // namespace cros_minidiag
