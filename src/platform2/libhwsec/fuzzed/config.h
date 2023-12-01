// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_CONFIG_H_
#define LIBHWSEC_FUZZED_CONFIG_H_

#include <memory>
#include <string>
#include <utility>

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/structures/device_config.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec/structures/permission.h"

namespace hwsec {

template <>
struct FuzzedObject<DeviceConfigSettings::BootModeSetting::Mode> {
  DeviceConfigSettings::BootModeSetting::Mode operator()(
      FuzzedDataProvider& provider) const {
    return DeviceConfigSettings::BootModeSetting::Mode{
        .developer_mode = provider.ConsumeBool(),
        .recovery_mode = provider.ConsumeBool(),
        .verified_firmware = provider.ConsumeBool(),
    };
  }
};

template <>
struct FuzzedObject<DeviceConfigSettings::BootModeSetting> {
  DeviceConfigSettings::BootModeSetting operator()(
      FuzzedDataProvider& provider) const {
    using Mode = DeviceConfigSettings::BootModeSetting::Mode;
    return DeviceConfigSettings::BootModeSetting{
        .mode = FuzzedObject<std::optional<Mode>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<DeviceConfigSettings::DeviceModelSetting> {
  DeviceConfigSettings::DeviceModelSetting operator()(
      FuzzedDataProvider& provider) const {
    return DeviceConfigSettings::DeviceModelSetting{
        .hardware_id = FuzzedObject<std::optional<std::string>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<DeviceConfigSettings::CurrentUserSetting> {
  DeviceConfigSettings::CurrentUserSetting operator()(
      FuzzedDataProvider& provider) const {
    return DeviceConfigSettings::CurrentUserSetting{
        .username = FuzzedObject<std::optional<std::string>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<DeviceConfigs> {
  DeviceConfigs operator()(FuzzedDataProvider& provider) const {
    DeviceConfigs device_configs;
    device_configs[DeviceConfig::kBootMode] = provider.ConsumeBool();
    device_configs[DeviceConfig::kDeviceModel] = provider.ConsumeBool();
    device_configs[DeviceConfig::kCurrentUser] = provider.ConsumeBool();
    return device_configs;
  }
};

template <>
struct FuzzedObject<DeviceConfigSettings> {
  DeviceConfigSettings operator()(FuzzedDataProvider& provider) const {
    using BootModeSetting = DeviceConfigSettings::BootModeSetting;
    using DeviceModelSetting = DeviceConfigSettings::DeviceModelSetting;
    using CurrentUserSetting = DeviceConfigSettings::CurrentUserSetting;
    return DeviceConfigSettings{
        .boot_mode = FuzzedObject<std::optional<BootModeSetting>>()(provider),
        .device_model =
            FuzzedObject<std::optional<DeviceModelSetting>>()(provider),
        .current_user =
            FuzzedObject<std::optional<CurrentUserSetting>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<Permission> {
  Permission operator()(FuzzedDataProvider& provider) const {
    return Permission{
        .type = FuzzedObject<PermissionType>()(provider),
        .auth_value =
            FuzzedObject<std::optional<brillo::SecureBlob>>()(provider),
    };
  }
};

template <>
struct FuzzedObject<OperationPolicy> {
  OperationPolicy operator()(FuzzedDataProvider& provider) const {
    return OperationPolicy{
        .device_configs = FuzzedObject<DeviceConfigs>()(provider),
        .permission = FuzzedObject<Permission>()(provider),
    };
  }
};

template <>
struct FuzzedObject<OperationPolicySetting> {
  OperationPolicySetting operator()(FuzzedDataProvider& provider) const {
    return OperationPolicySetting{
        .device_config_settings =
            FuzzedObject<DeviceConfigSettings>()(provider),
        .permission = FuzzedObject<Permission>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_CONFIG_H_
