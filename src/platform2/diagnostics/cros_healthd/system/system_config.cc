// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/system_config.h"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

#include <chromeos/chromeos-config/libcros_config/cros_config.h>
#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <brillo/errors/error.h>
#include <debugd/dbus-proxies.h>

#include "diagnostics/cros_healthd/system/debugd_constants.h"
#include "diagnostics/cros_healthd/system/system_config_constants.h"

namespace diagnostics {

namespace {

// The field that contains the bitvalue if the NVMe self test is supported by
// the device.
constexpr char kNvmeSelfTestCtrlField[] = "oacs";

// Bitmask for the bit that shows if the device supports the self test feature.
// 4th bit zero index.
constexpr uint8_t kNvmeSelfTestBitmask = 16;

bool NvmeSelfTestSupportedFromIdentity(const std::string& nvmeIdentity) {
  // Example output:
  // oacs      : 0x17
  // acl       : 3
  // aerl      : 7
  // frmw      : 0x16
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(nvmeIdentity, ':', '\n', &pairs);
  for (auto& p : pairs) {
    if (base::TrimWhitespaceASCII(p.first,
                                  base::TrimPositions::TRIM_TRAILING) !=
        kNvmeSelfTestCtrlField) {
      continue;
    }

    u_int32_t value;
    if (!base::HexStringToUInt(
            base::TrimWhitespaceASCII(p.second, base::TrimPositions::TRIM_ALL),
            &value)) {
      return false;
    }

    // Check to see if the device-self-test support bit is set
    return ((value & kNvmeSelfTestBitmask) == kNvmeSelfTestBitmask);
  }

  return false;
}

void NvmeSelfTestSupportedByDebugd(
    org::chromium::debugdProxyInterface* debugd_proxy,
    SystemConfig::NvmeSelfTestSupportedCallback callback) {
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  debugd_proxy->NvmeAsync(
      kNvmeIdentityOption,
      base::BindOnce(&NvmeSelfTestSupportedFromIdentity).Then(std::move(cb1)),
      base::BindOnce([](brillo::Error* error) {
      }).Then(base::BindOnce(std::move(cb2), false)));
}

std::string GetSensorPropertyName(SensorType sensor) {
  switch (sensor) {
    case kBaseAccelerometer:
      return kHasBaseAccelerometer;
    case kBaseGyroscope:
      return kHasBaseGyroscope;
    case kBaseMagnetometer:
      return kHasBaseMagnetometer;
    case kLidAccelerometer:
      return kHasLidAccelerometer;
    case kLidGyroscope:
      return kHasLidGyroscope;
    case kLidMagnetometer:
      return kHasLidMagnetometer;
    case kBaseGravitySensor:
    case kLidGravitySensor:
      // There are no |has-base-gravity-sensor| and |has-lid-gravity-sensor|
      // configurations.
      NOTREACHED_NORETURN();
  }
}

std::optional<bool> HasGravitySensor(std::optional<bool> has_accel,
                                     std::optional<bool> has_gyro) {
  if (!has_accel.has_value() || !has_gyro.has_value())
    return std::nullopt;
  return has_accel.value() && has_gyro.value();
}

}  // namespace

SystemConfig::SystemConfig(brillo::CrosConfigInterface* cros_config,
                           org::chromium::debugdProxyInterface* debugd_proxy)
    : SystemConfig(cros_config, debugd_proxy, base::FilePath("/")) {}

SystemConfig::SystemConfig(brillo::CrosConfigInterface* cros_config,
                           org::chromium::debugdProxyInterface* debugd_proxy,
                           const base::FilePath& root_dir)
    : cros_config_(cros_config),
      debugd_proxy_(debugd_proxy),
      root_dir_(root_dir) {
  DCHECK(cros_config_);
  DCHECK(debugd_proxy_);
}

SystemConfig::~SystemConfig() = default;

bool SystemConfig::HasBacklight() {
  std::string has_backlight;
  // Assume that device has a backlight unless otherwise configured.
  if (!cros_config_->GetString(kHardwarePropertiesPath, kHasBacklightProperty,
                               &has_backlight)) {
    return true;
  }
  return has_backlight != "false";
}

bool SystemConfig::HasBattery() {
  std::string psu_type;
  // Assume that device has a battery unless otherwise configured.
  if (!cros_config_->GetString(kHardwarePropertiesPath, kPsuTypeProperty,
                               &psu_type)) {
    return true;
  }
  return psu_type != "AC_only";
}

bool SystemConfig::HasSkuNumber() {
  std::string has_sku_number;
  // Assume that device have does NOT have a SKU number unless otherwise
  // configured.
  if (!cros_config_->GetString(kCachedVpdPropertiesPath, kHasSkuNumberProperty,
                               &has_sku_number)) {
    return false;
  }
  return has_sku_number == "true";
}

bool SystemConfig::HasSmartBattery() {
  std::string has_smart_battery_info;
  // Assume that device does NOT have a smart battery unless otherwise
  // configured.
  if (!cros_config_->GetString(kBatteryPropertiesPath,
                               kHasSmartBatteryInfoProperty,
                               &has_smart_battery_info)) {
    return false;
  }
  return has_smart_battery_info == "true";
}

bool SystemConfig::HasPrivacyScreen() {
  std::string has_privacy_screen;
  if (!cros_config_->GetString(kHardwarePropertiesPath,
                               kHasPrivacyScreenProperty,
                               &has_privacy_screen)) {
    return false;
  }
  return has_privacy_screen == "true";
}

bool SystemConfig::HasChromiumEC() {
  return base::PathExists(root_dir_.AppendASCII(kChromiumECPath));
}

bool SystemConfig::NvmeSupported() {
  return base::PathExists(root_dir_.AppendASCII(kNvmeToolPath)) &&
         !base::FileEnumerator(root_dir_.AppendASCII(kDevicePath), false,
                               base::FileEnumerator::FILES, "nvme*")
              .Next()
              .empty();
}

void SystemConfig::NvmeSelfTestSupported(
    NvmeSelfTestSupportedCallback callback) {
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  auto available_cb = base::BindOnce(&NvmeSelfTestSupportedByDebugd,
                                     debugd_proxy_, std::move(cb1));
  auto unavailable_cb = base::BindOnce(std::move(cb2), false);

  auto wait_service_cb = base::BindOnce(
      [](base::OnceClosure available_cb, base::OnceClosure unavailable_cb,
         bool service_is_available) {
        if (service_is_available) {
          std::move(available_cb).Run();
        } else {
          std::move(unavailable_cb).Run();
        }
      },
      std::move(available_cb), std::move(unavailable_cb));
  debugd_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      std::move(wait_service_cb));
}

bool SystemConfig::SmartCtlSupported() {
  return base::PathExists(root_dir_.AppendASCII(kSmartctlToolPath));
}

bool SystemConfig::MmcSupported() {
  return base::PathExists(root_dir_.AppendASCII(kMmcToolPath));
}

bool SystemConfig::FingerprintDiagnosticSupported() {
  std::string enable;
  if (!cros_config_->GetString(kFingerprintPropertiesPath,
                               kFingerprintRoutineEnable, &enable)) {
    return false;
  }
  return enable == "true";
}

bool SystemConfig::IsWilcoDevice() {
  const auto wilco_devices = GetWilcoBoardNames();
  return std::any_of(wilco_devices.begin(), wilco_devices.end(),
                     [](const std::string& s) -> bool {
                       // Check if the given wilco device name is a
                       // prefix for the actual board name.
                       return base::SysInfo::GetLsbReleaseBoard().rfind(s, 0) ==
                              0;
                     });
}

std::optional<std::string> SystemConfig::GetMarketingName() {
  std::string marketing_name;
  if (!cros_config_->GetString(kBrandingPath, kMarketingNameProperty,
                               &marketing_name)) {
    return std::nullopt;
  }
  return marketing_name;
}

std::optional<std::string> SystemConfig::GetOemName() {
  std::string oem_name;
  if (!cros_config_->GetString(kBrandingPath, kOemNameProperty, &oem_name)) {
    return std::nullopt;
  }
  return oem_name;
}

std::string SystemConfig::GetCodeName() {
  std::string code_name;
  if (!cros_config_->GetString(kRootPath, kCodeNameProperty, &code_name)) {
    // "/name" is a required field in cros config. This should not be reached in
    // normal situation. However, if in a device which is in the early
    // development stage or in a vm environment, this could still happen.
    return "";
  }
  return code_name;
}

std::optional<bool> SystemConfig::HasSensor(SensorType sensor) {
  // Gravity sensor is a virtual fusion sensor of accelerometer and gyroscope
  // instead of a hardware sensor. There is no static config for the gravity
  // sensor, but we can refer to the config of accelerometer and gyroscope.
  if (sensor == kBaseGravitySensor) {
    return HasGravitySensor(HasSensor(kBaseAccelerometer),
                            HasSensor(kBaseGyroscope));
  } else if (sensor == kLidGravitySensor) {
    return HasGravitySensor(HasSensor(kLidAccelerometer),
                            HasSensor(kLidGyroscope));
  }
  std::string has_sensor;
  if (!cros_config_->GetString(kHardwarePropertiesPath,
                               GetSensorPropertyName(sensor), &has_sensor)) {
    return std::nullopt;
  }
  return has_sensor == "true";
}

}  // namespace diagnostics
