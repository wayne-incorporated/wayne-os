// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_CONSTANTS_H_

#include <list>
#include <string>

namespace diagnostics {

// The path used to check a device's master configuration hardware properties.
inline constexpr char kHardwarePropertiesPath[] = "/hardware-properties";
// The master configuration property that specifies a device's PSU type.
inline constexpr char kPsuTypeProperty[] = "psu-type";
// The master configuration property that indicates whether a device has a
// built-in privacy screen.
inline constexpr char kHasPrivacyScreenProperty[] = "has-privacy-screen";
// The path used to check a device's master configuration cros_healthd battery
// properties.
inline constexpr char kBatteryPropertiesPath[] = "/cros-healthd/battery";
// The master configuration property that indicates whether a device has Smart
// Battery info.
inline constexpr char kHasSmartBatteryInfoProperty[] = "has-smart-battery-info";
// The master configuration property that indicates whether a device has a
// backlight.
inline constexpr char kHasBacklightProperty[] = "has-backlight";
// The path used to check a device's master configuration cros_healthd vpd
// properties.
inline constexpr char kCachedVpdPropertiesPath[] = "/cros-healthd/cached-vpd";
// The master configuration property that indicates whether a device has a
// sku number in the VPD fields.
inline constexpr char kHasSkuNumberProperty[] = "has-sku-number";
// The master configuration property that indicates whether a device has a base
// accelerometer.
inline constexpr char kHasBaseAccelerometer[] = "has-base-accelerometer";
// The master configuration property that indicates whether a device has a base
// gyroscope.
inline constexpr char kHasBaseGyroscope[] = "has-base-gyroscope";
// The master configuration property that indicates whether a device has a base
// magnetometer.
inline constexpr char kHasBaseMagnetometer[] = "has-base-magnetometer";
// The master configuration property that indicates whether a device has a lid
// accelerometer.
inline constexpr char kHasLidAccelerometer[] = "has-lid-accelerometer";
// The master configuration property that indicates whether a device has a lid
// gyroscope.
inline constexpr char kHasLidGyroscope[] = "has-lid-gyroscope";
// The master configuration property that indicates whether a device has a lid
// magnetometer.
inline constexpr char kHasLidMagnetometer[] = "has-lid-magnetometer";
// NVME utility program path relative to the root directory.
inline constexpr char kNvmeToolPath[] = "usr/sbin/nvme";
// Linux device path relative to the root directory.
inline constexpr char kDevicePath[] = "dev";
// Smartctl utility program path relative to the root directory.
inline constexpr char kSmartctlToolPath[] = "usr/sbin/smartctl";
// Mmc utility program path relative to the root directory.
inline constexpr char kMmcToolPath[] = "usr/bin/mmc";
// Fio utility program path relative to the root directory.
inline constexpr char kFioToolPath[] = "usr/bin/fio";
// Chromium EC path relative to the root directory.
inline constexpr char kChromiumECPath[] = "sys/class/chromeos/cros_ec";
// The path to check a device's branding properties.
inline constexpr char kBrandingPath[] = "/branding";
// The master configuration property that specifies a device's marketing name.
inline constexpr char kMarketingNameProperty[] = "marketing-name";
// The master configuration property that specifies a device's oem name.
inline constexpr char kOemNameProperty[] = "oem-name";
// The root path of master configuration.
inline constexpr char kRootPath[] = "/";
// The master configuration property that specifies a device's code name.
inline constexpr char kCodeNameProperty[] = "name";

// Returns a list of wilco board names.
inline const std::list<std::string> GetWilcoBoardNames() {
  return {"sarien", "drallion"};
}

// Fingerprint diagnostic related constants.
// The path used to retrieve the fingerprint diagnostic parameters.
inline constexpr char kFingerprintPropertiesPath[] =
    "/cros-healthd/routines/fingerprint-diag";
// The property indicates if the diagnostic is enabled or not.
inline constexpr char kFingerprintRoutineEnable[] = "routine-enable";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_CONSTANTS_H_
