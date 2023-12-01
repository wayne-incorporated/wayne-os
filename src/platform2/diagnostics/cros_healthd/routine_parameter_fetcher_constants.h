// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINE_PARAMETER_FETCHER_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINE_PARAMETER_FETCHER_CONSTANTS_H_

namespace diagnostics {

// Path to each routine's properties in cros_config.
inline constexpr char kBatteryCapacityPropertiesPath[] =
    "/cros-healthd/routines/battery-capacity";
inline constexpr char kBatteryHealthPropertiesPath[] =
    "/cros-healthd/routines/battery-health";
inline constexpr char kPrimeSearchPropertiesPath[] =
    "/cros-healthd/routines/prime-search";
inline constexpr char kNvmeWearLevelPropertiesPath[] =
    "/cros-healthd/routines/nvme-wear-level";
inline constexpr char kFingerprintPropertiesPath[] =
    "/cros-healthd/routines/fingerprint-diag";

// Battery capacity properties read from cros_config.
inline constexpr char kLowMahProperty[] = "low-mah";
inline constexpr char kHighMahProperty[] = "high-mah";

// Battery health properties read from cros_config.
inline constexpr char kMaximumCycleCountProperty[] = "maximum-cycle-count";
inline constexpr char kPercentBatteryWearAllowedProperty[] =
    "percent-battery-wear-allowed";

// Prime search property read from cros_config.
inline constexpr char kMaxNumProperty[] = "max-num";

// NVMe wear level property read from cros_config.
inline constexpr char kWearLevelThresholdProperty[] = "wear-level-threshold";

// Fingerprint routine properties read from cros_config.
inline constexpr char kMaxDeadPixels[] = "max-dead-pixels";
inline constexpr char kMaxDeadPixelsInDetectZone[] =
    "max-dead-pixels-in-detect-zone";
inline constexpr char kMaxPixelDev[] = "max-pixel-dev";
inline constexpr char kMaxErrorResetPixels[] = "max-error-reset-pixels";
inline constexpr char kMaxResetPixelDev[] = "max-reset-pixel-dev";
inline constexpr char kNumDetectZone[] = "num-detect-zone";
// Properties of pixel-median.
inline constexpr char kFingerprintPixelMedianPath[] =
    "/cros-healthd/routines/fingerprint-diag/pixel-median";
inline constexpr char kCbType1Lower[] = "cb-type1-lower";
inline constexpr char kCbType1Upper[] = "cb-type1-upper";
inline constexpr char kCbType2Lower[] = "cb-type2-lower";
inline constexpr char kCbType2Upper[] = "cb-type2-upper";
inline constexpr char kIcbType1Lower[] = "icb-type1-lower";
inline constexpr char kIcbType1Upper[] = "icb-type1-upper";
inline constexpr char kIcbType2Lower[] = "icb-type2-lower";
inline constexpr char kIcbType2Upper[] = "icb-type2-upper";
// Properties of detect-zones.
inline constexpr char kFingerprintDetectZonesPath[] =
    "/cros-healthd/routines/fingerprint-diag/detect-zones";
inline constexpr char kX1[] = "x1";
inline constexpr char kY1[] = "y1";
inline constexpr char kX2[] = "x2";
inline constexpr char kY2[] = "y2";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINE_PARAMETER_FETCHER_CONSTANTS_H_
