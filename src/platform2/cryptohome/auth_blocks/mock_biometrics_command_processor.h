// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_MOCK_BIOMETRICS_COMMAND_PROCESSOR_H_
#define CRYPTOHOME_AUTH_BLOCKS_MOCK_BIOMETRICS_COMMAND_PROCESSOR_H_

#include "cryptohome/auth_blocks/biometrics_command_processor.h"

#include <string>
#include <optional>

#include <gmock/gmock.h>

namespace cryptohome {

class MockBiometricsCommandProcessor : public BiometricsCommandProcessor {
 public:
  MockBiometricsCommandProcessor() = default;
  MOCK_METHOD(
      void,
      SetEnrollScanDoneCallback,
      (base::RepeatingCallback<void(user_data_auth::AuthEnrollmentProgress,
                                    std::optional<brillo::Blob>)>),
      (override));
  MOCK_METHOD(bool, IsReady, (), (override));
  MOCK_METHOD(void,
              SetAuthScanDoneCallback,
              (base::RepeatingCallback<void(user_data_auth::AuthScanDone,
                                            brillo::Blob)>),
              (override));
  MOCK_METHOD(void,
              SetSessionFailedCallback,
              (base::RepeatingCallback<void()>),
              (override));
  MOCK_METHOD(void,
              StartEnrollSession,
              (base::OnceCallback<void(bool)>),
              (override));
  MOCK_METHOD(void,
              StartAuthenticateSession,
              (ObfuscatedUsername, base::OnceCallback<void(bool)>),
              (override));
  MOCK_METHOD(void,
              CreateCredential,
              (ObfuscatedUsername, OperationInput, OperationCallback),
              (override));
  MOCK_METHOD(void,
              MatchCredential,
              (OperationInput, OperationCallback),
              (override));
  MOCK_METHOD(void, EndEnrollSession, (), (override));
  MOCK_METHOD(void, EndAuthenticateSession, (), (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_MOCK_BIOMETRICS_COMMAND_PROCESSOR_H_
