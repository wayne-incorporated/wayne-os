// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_TPM_STATE_H_
#define TRUNKS_MOCK_TPM_STATE_H_

#include <string>

#include <gmock/gmock.h>

#include "trunks/tpm_state.h"

namespace trunks {

class MockTpmState : public TpmState {
 public:
  MockTpmState();
  ~MockTpmState() override;

  MOCK_METHOD0(Initialize, TPM_RC());
  MOCK_METHOD0(IsOwnerPasswordSet, bool());
  MOCK_METHOD0(IsEndorsementPasswordSet, bool());
  MOCK_METHOD0(IsLockoutPasswordSet, bool());
  MOCK_METHOD0(IsOwned, bool());
  MOCK_METHOD0(IsInLockout, bool());
  MOCK_METHOD0(IsPlatformHierarchyEnabled, bool());
  MOCK_METHOD0(IsStorageHierarchyEnabled, bool());
  MOCK_METHOD0(IsEndorsementHierarchyEnabled, bool());
  MOCK_METHOD0(IsEnabled, bool());
  MOCK_METHOD0(WasShutdownOrderly, bool());
  MOCK_METHOD0(IsRSASupported, bool());
  MOCK_METHOD0(IsECCSupported, bool());
  MOCK_METHOD0(GetLockoutCounter, uint32_t());
  MOCK_METHOD0(GetLockoutThreshold, uint32_t());
  MOCK_METHOD0(GetLockoutInterval, uint32_t());
  MOCK_METHOD0(GetLockoutRecovery, uint32_t());
  MOCK_METHOD0(GetMaxNVSize, uint32_t());
  MOCK_METHOD0(GetTpmFamily, uint32_t());
  MOCK_METHOD0(GetSpecificationLevel, uint32_t());
  MOCK_METHOD0(GetSpecificationRevision, uint32_t());
  MOCK_METHOD0(GetManufacturer, uint32_t());
  MOCK_METHOD0(GetTpmModel, uint32_t());
  MOCK_METHOD0(GetFirmwareVersion, uint64_t());
  MOCK_METHOD0(GetVendorIDString, std::string());
  MOCK_METHOD2(GetTpmProperty, bool(TPM_PT, uint32_t*));
  MOCK_METHOD2(GetAlgorithmProperties, bool(TPM_ALG_ID, TPMA_ALGORITHM*));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_TPM_STATE_H_
