// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_tpm_status.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SetArgPointee;

namespace tpm_manager {

bool GetDefaultDictionaryAttackInfo(uint32_t* counter,
                                    uint32_t* threshold,
                                    bool* lockout,
                                    uint32_t* seconds_remaining) {
  *counter = 0;
  *threshold = 10;
  *lockout = false;
  *seconds_remaining = 0;
  return true;
}

bool GetDefaultVersionInfo(uint32_t* family,
                           uint64_t* spec_level,
                           uint32_t* manufacturer,
                           uint32_t* tpm_model,
                           uint64_t* firmware_version,
                           std::vector<uint8_t>* vendor_specific) {
  *family = 0x312e3200;
  *spec_level = (0ULL << 32) | 138;
  *manufacturer = 0x90091;
  *tpm_model = 0x1234;
  *firmware_version = 0xdeadc0de;
  *vendor_specific = {0xda, 0x7a};
  return true;
}

MockTpmStatus::MockTpmStatus() {
  ON_CALL(*this, IsTpmEnabled()).WillByDefault(Return(true));

  ON_CALL(*this, GetTpmOwned(_))
      .WillByDefault(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));

  ON_CALL(*this, GetDictionaryAttackInfo(_, _, _, _))
      .WillByDefault(Invoke(GetDefaultDictionaryAttackInfo));
  ON_CALL(*this, IsDictionaryAttackMitigationEnabled(_))
      .WillByDefault(DoAll(SetArgPointee<0>(true), Return(true)));
  ON_CALL(*this, GetVersionInfo(_, _, _, _, _, _))
      .WillByDefault(Invoke(GetDefaultVersionInfo));
}
MockTpmStatus::~MockTpmStatus() {}

}  // namespace tpm_manager
