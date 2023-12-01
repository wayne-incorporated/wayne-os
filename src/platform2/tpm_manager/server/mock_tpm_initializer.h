// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_INITIALIZER_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_INITIALIZER_H_

#include "tpm_manager/server/tpm_initializer.h"

#include <string>

#include <gmock/gmock.h>

namespace tpm_manager {

class MockTpmInitializer : public TpmInitializer {
 public:
  MockTpmInitializer();
  ~MockTpmInitializer() override;

  MOCK_METHOD(bool, PreInitializeTpm, (), (override));
  MOCK_METHOD(bool, InitializeTpm, (bool*), (override));
  MOCK_METHOD(bool, EnsurePersistentOwnerDelegate, (), (override));
  MOCK_METHOD(void, VerifiedBootHelper, (), (override));
  MOCK_METHOD(DictionaryAttackResetStatus,
              ResetDictionaryAttackLock,
              (),
              (override));
  MOCK_METHOD(TpmInitializerStatus,
              DisableDictionaryAttackMitigation,
              (),
              (override));
  MOCK_METHOD(void, PruneStoredPasswords, (), (override));
  MOCK_METHOD(bool,
              ChangeOwnerPassword,
              (const std::string&, const std::string&),
              (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_INITIALIZER_H_
