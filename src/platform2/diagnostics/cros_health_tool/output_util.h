// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_OUTPUT_UTIL_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_OUTPUT_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/values.h>

#include "diagnostics/mojom/external/network_health_types.mojom.h"
#include "diagnostics/mojom/external/network_types.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

std::string EnumToString(ash::cros_healthd::mojom::ProcessState state);
std::string EnumToString(ash::cros_healthd::mojom::ErrorType type);
std::string EnumToString(
    ash::cros_healthd::mojom::CpuArchitectureEnum architecture);
std::string EnumToString(chromeos::network_config::mojom::NetworkType type);
std::string EnumToString(chromeos::network_health::mojom::NetworkState state);
std::string EnumToString(chromeos::network_config::mojom::PortalState state);
std::string EnumToString(
    ash::cros_healthd::mojom::EncryptionState encryption_state);
std::string EnumToString(ash::cros_healthd::mojom::CryptoAlgorithm algorithm);
std::string EnumToString(ash::cros_healthd::mojom::BusDeviceClass device_class);
std::string EnumToString(
    ash::cros_healthd::mojom::FwupdVersionFormat fwupd_version_format);
std::string EnumToString(ash::cros_healthd::mojom::BootMode mode);
std::string EnumToString(ash::cros_healthd::mojom::TpmGSCVersion version);
std::string EnumToString(
    ash::cros_healthd::mojom::ThunderboltSecurityLevel level);
std::optional<std::string> EnumToString(
    ash::cros_healthd::mojom::BluetoothDeviceType type);
std::string EnumToString(
    ash::cros_healthd::mojom::VulnerabilityInfo::Status status);
std::string EnumToString(
    ash::cros_healthd::mojom::CpuVirtualizationInfo::Type type);
std::string EnumToString(
    ash::cros_healthd::mojom::VirtualizationInfo::SMTControl control);
std::string EnumToString(
    ash::cros_healthd::mojom::InputDevice::ConnectionType type);
std::optional<std::string> EnumToString(
    ash::cros_healthd::mojom::DisplayInputType type);
std::string EnumToString(
    ash::cros_healthd::mojom::OsInfo::EfiPlatformSize size);
std::string EnumToString(ash::cros_healthd::mojom::Sensor::Type type);
std::string EnumToString(ash::cros_healthd::mojom::Sensor::Location type);
std::string EnumToString(ash::cros_healthd::mojom::UsbVersion version);
std::string EnumToString(ash::cros_healthd::mojom::UsbSpecSpeed spec_speed);
std::string EnumToString(ash::cros_healthd::mojom::PsrInfo::LogState state);
std::string EnumToString(ash::cros_healthd::mojom::PsrEvent::EventType type);
std::string EnumToString(ash::cros_healthd::mojom::MemtesterTestItemEnum test);

#define SET_DICT(key, info, output) SetJsonDictValue(#key, info->key, output);

template <typename T>
void SetJsonDictValue(const std::string& key,
                      const T& value,
                      base::Value::Dict* output) {
  if constexpr (std::is_same_v<T, uint32_t> || std::is_same_v<T, int64_t> ||
                std::is_same_v<T, uint64_t>) {
    // |base::Value| doesn't support these types, we need to convert them to
    // string.
    SetJsonDictValue(key, base::NumberToString(value), output);
  } else if constexpr (std::is_same_v<T, std::optional<std::string>>) {
    if (value.has_value())
      SetJsonDictValue(key, value.value(), output);
    // TODO(b/194872701)
    // NOLINTNEXTLINE(readability/braces)
  } else if constexpr (std::is_same_v<
                           T, std::optional<std::vector<std::string>>>) {
    if (value.has_value())
      SetJsonDictValue(key, value.value(), output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableDoublePtr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableUint8Ptr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableInt16Ptr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableUint16Ptr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableUint32Ptr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_same_v<
                           T, ash::cros_healthd::mojom::NullableUint64Ptr>) {
    if (value)
      SetJsonDictValue(key, value->value, output);
    // TODO(b/194872701): This line cannot be broken because the linter issue.
    // clang-format off
  } else if constexpr (std::is_same_v<
                           T, chromeos::network_health::mojom::UInt32ValuePtr>){
    // clang-format on
    if (value)
      SetJsonDictValue(key, value->value, output);
  } else if constexpr (std::is_enum_v<T>) {
    SetJsonDictValue(key, EnumToString(value), output);
    // TODO(b/194872701)
    // NOLINTNEXTLINE(readability/braces)
  } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
    base::Value::List string_vector;
    for (const auto& s : value)
      string_vector.Append(s);
    output->Set(key, std::move(string_vector));
  } else {
    output->Set(key, value);
  }
}

void OutputJson(const base::Value::Dict& output);

void OutputSingleLineJson(const base::Value::Dict& output);

void OutputSupportStatus(
    const ash::cros_healthd::mojom::SupportStatusPtr status);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_OUTPUT_UTIL_H_
