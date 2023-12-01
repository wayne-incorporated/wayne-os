// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_CROS_FP_DEVICE_H_
#define BIOD_MOCK_CROS_FP_DEVICE_H_

#include <bitset>
#include <memory>
#include <optional>
#include <string>

#include <libec/fingerprint/cros_fp_device_interface.h>
#include <libec/fingerprint/fp_mode.h>

namespace biod {

class MockCrosFpDevice : public ec::CrosFpDeviceInterface {
 public:
  MockCrosFpDevice() = default;
  ~MockCrosFpDevice() override = default;

  MOCK_METHOD(void, SetMkbpEventCallback, (MkbpCallback), (override));
  MOCK_METHOD(bool, SetFpMode, (const ec::FpMode& mode), (override));
  MOCK_METHOD(ec::FpMode, GetFpMode, (), (override));
  MOCK_METHOD(std::optional<FpStats>, GetFpStats, (), (override));
  MOCK_METHOD(std::optional<std::bitset<32>>, GetDirtyMap, (), (override));
  MOCK_METHOD(std::unique_ptr<VendorTemplate>,
              GetTemplate,
              (int index),
              (override));
  MOCK_METHOD(bool, UploadTemplate, (const VendorTemplate& tmpl), (override));
  MOCK_METHOD(bool, SetContext, (std::string user_id), (override));
  MOCK_METHOD(bool, ResetContext, (), (override));
  MOCK_METHOD(bool, InitEntropy, (bool reset), (override));
  MOCK_METHOD(bool, UpdateFpInfo, (), (override));
  MOCK_METHOD(int, MaxTemplateCount, (), (override));
  MOCK_METHOD(int, TemplateVersion, (), (override));
  MOCK_METHOD(int, DeadPixelCount, (), (override));
  MOCK_METHOD(ec::FpSensorErrors, GetHwErrors, (), (override));
  MOCK_METHOD(ec::EcCmdVersionSupportStatus,
              EcCmdVersionSupported,
              (uint16_t cmd, uint32_t ver),
              (override));
  MOCK_METHOD(bool, SupportsPositiveMatchSecret, (), (override));
  MOCK_METHOD(std::optional<brillo::SecureVector>,
              GetPositiveMatchSecret,
              (int index),
              (override));
};

}  // namespace biod

#endif  // BIOD_MOCK_CROS_FP_DEVICE_H_
