// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_VENDOR_H_
#define LIBHWSEC_BACKEND_MOCK_VENDOR_H_

#include <cstdint>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/vendor.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockVendor : public Vendor {
 public:
  MockVendor() = default;
  explicit MockVendor(Vendor* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, GetFamily)
        .WillByDefault(Invoke(default_, &Vendor::GetFamily));
    ON_CALL(*this, GetSpecLevel)
        .WillByDefault(Invoke(default_, &Vendor::GetSpecLevel));
    ON_CALL(*this, GetManufacturer)
        .WillByDefault(Invoke(default_, &Vendor::GetManufacturer));
    ON_CALL(*this, GetTpmModel)
        .WillByDefault(Invoke(default_, &Vendor::GetTpmModel));
    ON_CALL(*this, GetFirmwareVersion)
        .WillByDefault(Invoke(default_, &Vendor::GetFirmwareVersion));
    ON_CALL(*this, GetVendorSpecific)
        .WillByDefault(Invoke(default_, &Vendor::GetVendorSpecific));
    ON_CALL(*this, GetFingerprint)
        .WillByDefault(Invoke(default_, &Vendor::GetFingerprint));
    ON_CALL(*this, IsSrkRocaVulnerable)
        .WillByDefault(Invoke(default_, &Vendor::IsSrkRocaVulnerable));
    ON_CALL(*this, GetRsuDeviceId)
        .WillByDefault(Invoke(default_, &Vendor::GetRsuDeviceId));
    ON_CALL(*this, GetIFXFieldUpgradeInfo)
        .WillByDefault(Invoke(default_, &Vendor::GetIFXFieldUpgradeInfo));
    ON_CALL(*this, DeclareTpmFirmwareStable)
        .WillByDefault(Invoke(default_, &Vendor::DeclareTpmFirmwareStable));
    ON_CALL(*this, GetRwVersion)
        .WillByDefault(Invoke(default_, &Vendor::GetRwVersion));
    ON_CALL(*this, SendRawCommand)
        .WillByDefault(Invoke(default_, &Vendor::SendRawCommand));
  }

  MOCK_METHOD(StatusOr<uint32_t>, GetFamily, (), (override));
  MOCK_METHOD(StatusOr<uint64_t>, GetSpecLevel, (), (override));
  MOCK_METHOD(StatusOr<uint32_t>, GetManufacturer, (), (override));
  MOCK_METHOD(StatusOr<uint32_t>, GetTpmModel, (), (override));
  MOCK_METHOD(StatusOr<uint64_t>, GetFirmwareVersion, (), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetVendorSpecific, (), (override));
  MOCK_METHOD(StatusOr<int32_t>, GetFingerprint, (), (override));
  MOCK_METHOD(StatusOr<bool>, IsSrkRocaVulnerable, (), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetRsuDeviceId, (), (override));
  MOCK_METHOD(StatusOr<IFXFieldUpgradeInfo>,
              GetIFXFieldUpgradeInfo,
              (),
              (override));
  MOCK_METHOD(Status, DeclareTpmFirmwareStable, (), (override));
  MOCK_METHOD(StatusOr<RwVersion>, GetRwVersion, (), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              SendRawCommand,
              (const brillo::Blob& command),
              (override));

 private:
  Vendor* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_VENDOR_H_
