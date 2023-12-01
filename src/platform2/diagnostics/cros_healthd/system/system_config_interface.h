// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_INTERFACE_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_INTERFACE_H_

#include <optional>
#include <string>

#include <base/functional/callback.h>

namespace diagnostics {

enum SensorType {
  kBaseAccelerometer,
  kBaseGyroscope,
  kBaseMagnetometer,
  kBaseGravitySensor,
  kLidAccelerometer,
  kLidGyroscope,
  kLidMagnetometer,
  kLidGravitySensor,
};

class SystemConfigInterface {
 public:
  using NvmeSelfTestSupportedCallback = base::OnceCallback<void(bool)>;

  virtual ~SystemConfigInterface() = default;

  // Returns if the device has a backlight.
  virtual bool HasBacklight() = 0;

  // Returns if the device has a battery (e.g. not a Chromebox).
  virtual bool HasBattery() = 0;

  // Returns if the device has a SKU number in the VPD fields.
  virtual bool HasSkuNumber() = 0;

  // Returns if the device has a battery with SMART features.
  virtual bool HasSmartBattery() = 0;

  // Returns if this board/SKU is marked to have a built-in privacy screen.
  virtual bool HasPrivacyScreen() = 0;

  // Returns if the device has a Chromium EC.
  virtual bool HasChromiumEC() = 0;

  // Returns if the device has an Nvme drive and the associated utilities.
  virtual bool NvmeSupported() = 0;

  // Get whether the device can run the Nvme device-self-test command and pass
  // the result to |callback|. It will wait until debugd to be available before
  // it queries debugd.
  virtual void NvmeSelfTestSupported(
      NvmeSelfTestSupportedCallback callback) = 0;

  // Returns if the device has support for smartctl.
  virtual bool SmartCtlSupported() = 0;

  // Returns if the device has support for mmc.
  virtual bool MmcSupported() = 0;

  // Returns if the device supports fingerprint diagnostics.
  virtual bool FingerprintDiagnosticSupported() = 0;

  // Returns if the device has support for wilco features. See go/wilco for more
  // details.
  virtual bool IsWilcoDevice() = 0;

  // Returns the marketing name associated with this device.
  virtual std::optional<std::string> GetMarketingName() = 0;

  // Returns the oem name associated with this device.
  virtual std::optional<std::string> GetOemName() = 0;

  // Returns the code name associated with this device.
  virtual std::string GetCodeName() = 0;

  // Returns if the device has a sensor of type |sensor|.
  virtual std::optional<bool> HasSensor(SensorType sensor) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_CONFIG_INTERFACE_H_
