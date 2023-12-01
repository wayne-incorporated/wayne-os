// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_OWNERSHIP_INTERFACE_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_OWNERSHIP_INTERFACE_H_

#include <gmock/gmock.h>

#include "tpm_manager/server/tpm_ownership_interface.h"

namespace tpm_manager {

class MockTpmOwnershipInterface : public TpmOwnershipInterface {
 public:
  MockTpmOwnershipInterface();
  ~MockTpmOwnershipInterface() override;

  MOCK_METHOD(void,
              GetTpmStatus,
              (const GetTpmStatusRequest&, GetTpmStatusCallback),
              (override));
  MOCK_METHOD(void,
              GetTpmNonsensitiveStatus,
              (const GetTpmNonsensitiveStatusRequest&,
               GetTpmNonsensitiveStatusCallback),
              (override));
  MOCK_METHOD(void,
              GetVersionInfo,
              (const GetVersionInfoRequest&, GetVersionInfoCallback),
              (override));
  MOCK_METHOD(void,
              GetSupportedFeatures,
              (const GetSupportedFeaturesRequest&,
               GetSupportedFeaturesCallback),
              (override));
  MOCK_METHOD(void,
              GetDictionaryAttackInfo,
              (const GetDictionaryAttackInfoRequest&,
               GetDictionaryAttackInfoCallback),
              (override));
  MOCK_METHOD(void,
              GetRoVerificationStatus,
              (const GetRoVerificationStatusRequest&,
               GetRoVerificationStatusCallback),
              (override));
  MOCK_METHOD(void,
              ResetDictionaryAttackLock,
              (const ResetDictionaryAttackLockRequest&,
               ResetDictionaryAttackLockCallback),
              (override));
  MOCK_METHOD(void,
              TakeOwnership,
              (const TakeOwnershipRequest&, TakeOwnershipCallback),
              (override));
  MOCK_METHOD(void,
              RemoveOwnerDependency,
              (const RemoveOwnerDependencyRequest&,
               RemoveOwnerDependencyCallback),
              (override));
  MOCK_METHOD(void,
              ClearStoredOwnerPassword,
              (const ClearStoredOwnerPasswordRequest&,
               ClearStoredOwnerPasswordCallback),
              (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_OWNERSHIP_INTERFACE_H_
