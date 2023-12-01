// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_CONSTANTS_H_

namespace diagnostics {

namespace cros_config_path {

inline constexpr char kHardwareProperties[] = "/hardware-properties";

}  // namespace cros_config_path

namespace cros_config_property {

inline constexpr char kFormFactor[] = "form-factor";
inline constexpr char kStylusCategory[] = "stylus-category";
inline constexpr char kHasTouchscreen[] = "has-touchscreen";
inline constexpr char kHasHdmi[] = "has-hdmi";
inline constexpr char kHasAudioJack[] = "has-audio-jack";
inline constexpr char kHasSdReader[] = "has-sd-reader";
inline constexpr char kStorageType[] = "storage-type";

}  // namespace cros_config_property

namespace cros_config_value {

// Possible values of /hardware-properties/form-factor.
inline constexpr char kClamshell[] = "CLAMSHELL";
inline constexpr char kConvertible[] = "CONVERTIBLE";
inline constexpr char kDetachable[] = "DETACHABLE";
inline constexpr char kChromebase[] = "CHROMEBASE";
inline constexpr char kChromebox[] = "CHROMEBOX";
inline constexpr char kChromebit[] = "CHROMEBIT";
inline constexpr char kChromeslate[] = "CHROMESLATE";

// Possible values of /hardware-properties/stylus-category.
inline constexpr char kStylusCategoryUnknown[] = "unknown";
inline constexpr char kStylusCategoryNone[] = "none";
inline constexpr char kStylusCategoryInternal[] = "internal";
inline constexpr char kStylusCategoryExternal[] = "external";

// Possible values of /hardware-properties/storage-type.
inline constexpr char kStorageTypeUnknown[] = "STORAGE_TYPE_UNKNOWN";
inline constexpr char kStorageTypeEmmc[] = "EMMC";
inline constexpr char kStorageTypeNvme[] = "NVME";
inline constexpr char kStorageTypeSata[] = "SATA";
inline constexpr char kStorageTypeUfs[] = "UFS";
inline constexpr char kStorageTypeBridgedEmmc[] = "BRIDGED_EMMC";

}  // namespace cros_config_value

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_CONSTANTS_H_
