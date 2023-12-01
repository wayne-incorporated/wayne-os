// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_CONFIG_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_CONFIG_H_

#include <map>
#include <optional>
#include <string>

#include "diagnostics/cros_healthd/system/system_config_interface.h"

namespace diagnostics {

class FakeSystemConfig final : public SystemConfigInterface {
 public:
  FakeSystemConfig();
  FakeSystemConfig(const FakeSystemConfig&) = delete;
  FakeSystemConfig& operator=(const FakeSystemConfig&) = delete;
  ~FakeSystemConfig() override;

  // SystemConfigInterface overrides.
  bool HasBacklight() override;
  bool HasBattery() override;
  bool HasSmartBattery() override;
  bool HasSkuNumber() override;
  bool HasPrivacyScreen() override;
  bool HasChromiumEC() override;
  bool NvmeSupported() override;
  void NvmeSelfTestSupported(NvmeSelfTestSupportedCallback callback) override;
  bool SmartCtlSupported() override;
  bool MmcSupported() override;
  bool FingerprintDiagnosticSupported() override;
  bool IsWilcoDevice() override;
  std::optional<std::string> GetMarketingName() override;
  std::optional<std::string> GetOemName() override;
  std::string GetCodeName() override;
  std::optional<bool> HasSensor(SensorType sensor) override;

  // Setters for FakeSystemConfig attributes.
  void SetHasBacklight(bool value);
  void SetHasBattery(bool value);
  void SetHasSmartBattery(bool value);
  void SetHasSkuNumber(bool value);
  void SetHasPrivacyScreen(bool value);
  void SetHasChromiumEC(bool value);
  void SetNvmeSupported(bool value);
  void SetNvmeSelfTestSupported(bool value);
  void SetSmartCtrlSupported(bool value);
  void SetMmcSupported(bool value);
  void SetFingerprintDiagnosticSupported(bool value);
  void SetIsWilcoDevice(bool value);
  void SetMarketingName(const std::optional<std::string>& value);
  void SetOemName(const std::optional<std::string>& value);
  void SetCodeName(const std::string& value);
  void SetSensor(SensorType sensor, const std::optional<bool>& value);

 private:
  bool has_backlight_ = true;
  bool has_battery_ = true;
  bool has_smart_battery_ = true;
  bool has_sku_number_property_ = true;
  bool has_privacy_screen_ = true;
  bool has_chromium_ec_ = true;
  bool nvme_supported_ = true;
  bool nvme_self_test_supported_ = true;
  bool smart_ctrl_supported_ = true;
  bool mmc_supported_ = true;
  bool fingerprint_diagnostic_supported_ = true;
  bool wilco_device_ = true;
  std::optional<std::string> marketing_name_;
  std::optional<std::string> oem_name_;
  std::string code_name_;
  std::map<SensorType, std::optional<bool>> has_sensors_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_CONFIG_H_
