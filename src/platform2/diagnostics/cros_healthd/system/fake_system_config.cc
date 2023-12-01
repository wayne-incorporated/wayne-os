// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/fake_system_config.h"

#include <optional>
#include <utility>

namespace diagnostics {

FakeSystemConfig::FakeSystemConfig() = default;
FakeSystemConfig::~FakeSystemConfig() = default;

bool FakeSystemConfig::HasBacklight() {
  return has_backlight_;
}

bool FakeSystemConfig::HasBattery() {
  return has_battery_;
}

bool FakeSystemConfig::HasSmartBattery() {
  return has_smart_battery_;
}

bool FakeSystemConfig::HasSkuNumber() {
  return has_sku_number_property_;
}

bool FakeSystemConfig::HasPrivacyScreen() {
  return has_privacy_screen_;
}

bool FakeSystemConfig::HasChromiumEC() {
  return has_chromium_ec_;
}

bool FakeSystemConfig::NvmeSupported() {
  return nvme_supported_;
}

void FakeSystemConfig::NvmeSelfTestSupported(
    NvmeSelfTestSupportedCallback callback) {
  std::move(callback).Run(nvme_self_test_supported_);
}

bool FakeSystemConfig::SmartCtlSupported() {
  return smart_ctrl_supported_;
}

bool FakeSystemConfig::MmcSupported() {
  return mmc_supported_;
}

bool FakeSystemConfig::FingerprintDiagnosticSupported() {
  return fingerprint_diagnostic_supported_;
}

bool FakeSystemConfig::IsWilcoDevice() {
  return wilco_device_;
}

std::optional<std::string> FakeSystemConfig::GetMarketingName() {
  return marketing_name_;
}

std::optional<std::string> FakeSystemConfig::GetOemName() {
  return oem_name_;
}

std::string FakeSystemConfig::GetCodeName() {
  return code_name_;
}

std::optional<bool> FakeSystemConfig::HasSensor(SensorType sensor) {
  return has_sensors_[sensor];
}

void FakeSystemConfig::SetHasBacklight(bool value) {
  has_backlight_ = value;
}

void FakeSystemConfig::SetHasBattery(bool value) {
  has_battery_ = value;
}

void FakeSystemConfig::SetHasPrivacyScreen(bool value) {
  has_privacy_screen_ = value;
}

void FakeSystemConfig::SetHasChromiumEC(bool value) {
  has_chromium_ec_ = value;
}

void FakeSystemConfig::SetHasSmartBattery(bool value) {
  has_smart_battery_ = value;
}

void FakeSystemConfig::SetHasSkuNumber(bool value) {
  has_sku_number_property_ = value;
}

void FakeSystemConfig::SetNvmeSupported(bool value) {
  nvme_supported_ = value;
}

void FakeSystemConfig::SetNvmeSelfTestSupported(bool value) {
  nvme_self_test_supported_ = value;
}

void FakeSystemConfig::SetSmartCtrlSupported(bool value) {
  smart_ctrl_supported_ = value;
}

void FakeSystemConfig::SetMmcSupported(bool value) {
  mmc_supported_ = value;
}

void FakeSystemConfig::SetFingerprintDiagnosticSupported(bool value) {
  fingerprint_diagnostic_supported_ = value;
}

void FakeSystemConfig::SetIsWilcoDevice(bool value) {
  wilco_device_ = value;
}

void FakeSystemConfig::SetMarketingName(
    const std::optional<std::string>& value) {
  marketing_name_ = value;
}

void FakeSystemConfig::SetOemName(const std::optional<std::string>& value) {
  oem_name_ = value;
}

void FakeSystemConfig::SetCodeName(const std::string& value) {
  code_name_ = value;
}

void FakeSystemConfig::SetSensor(SensorType sensor,
                                 const std::optional<bool>& value) {
  has_sensors_[sensor] = value;
}

}  // namespace diagnostics
