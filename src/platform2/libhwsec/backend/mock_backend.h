// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_BACKEND_H_
#define LIBHWSEC_BACKEND_MOCK_BACKEND_H_

#include <memory>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// Allow using the backend interface via mock backend.
#define LIBHWSEC_MOCK_BACKEND

#include "libhwsec/backend/backend.h"
#include "libhwsec/backend/mock_attestation.h"
#include "libhwsec/backend/mock_config.h"
#include "libhwsec/backend/mock_da_mitigation.h"
#include "libhwsec/backend/mock_deriving.h"
#include "libhwsec/backend/mock_encryption.h"
#include "libhwsec/backend/mock_key_management.h"
#include "libhwsec/backend/mock_pinweaver.h"
#include "libhwsec/backend/mock_random.h"
#include "libhwsec/backend/mock_recovery_crypto.h"
#include "libhwsec/backend/mock_ro_data.h"
#include "libhwsec/backend/mock_sealing.h"
#include "libhwsec/backend/mock_session_management.h"
#include "libhwsec/backend/mock_signature_sealing.h"
#include "libhwsec/backend/mock_signing.h"
#include "libhwsec/backend/mock_state.h"
#include "libhwsec/backend/mock_storage.h"
#include "libhwsec/backend/mock_u2f.h"
#include "libhwsec/backend/mock_vendor.h"
#include "libhwsec/backend/mock_version_attestation.h"

namespace hwsec {

class MockBackend : public Backend {
 public:
  struct MockBackendData {
    testing::NiceMock<MockState> state;
    testing::NiceMock<MockDAMitigation> da_mitigation;
    testing::NiceMock<MockStorage> storage;
    testing::NiceMock<MockRoData> ro_data;
    testing::NiceMock<MockSealing> sealing;
    testing::NiceMock<MockSignatureSealing> signature_sealing;
    testing::NiceMock<MockDeriving> deriving;
    testing::NiceMock<MockEncryption> encryption;
    testing::NiceMock<MockSigning> signing;
    testing::NiceMock<MockKeyManagement> key_management;
    testing::NiceMock<MockSessionManagement> session_management;
    testing::NiceMock<MockConfig> config;
    testing::NiceMock<MockRandom> random;
    testing::NiceMock<MockPinWeaver> pinweaver;
    testing::NiceMock<MockVendor> vendor;
    testing::NiceMock<MockRecoveryCrypto> recovery_crypto;
    testing::NiceMock<MockU2f> u2f;
    testing::NiceMock<MockAttestation> attestation;
    testing::NiceMock<MockVersionAttestation> version_attestation;
  };

  MockBackend() = default;
  explicit MockBackend(std::unique_ptr<Backend> backend)
      : default_backend_(std::move(backend)),
        mock_data_(MockBackendData{
            .state =
                testing::NiceMock<MockState>(default_backend_->Get<State>()),
            .da_mitigation = testing::NiceMock<MockDAMitigation>(
                default_backend_->Get<DAMitigation>()),
            .storage = testing::NiceMock<MockStorage>(
                default_backend_->Get<Storage>()),
            .ro_data =
                testing::NiceMock<MockRoData>(default_backend_->Get<RoData>()),
            .sealing = testing::NiceMock<MockSealing>(
                default_backend_->Get<Sealing>()),
            .signature_sealing = testing::NiceMock<MockSignatureSealing>(
                default_backend_->Get<SignatureSealing>()),
            .deriving = testing::NiceMock<MockDeriving>(
                default_backend_->Get<Deriving>()),
            .encryption = testing::NiceMock<MockEncryption>(
                default_backend_->Get<Encryption>()),
            .signing = testing::NiceMock<MockSigning>(
                default_backend_->Get<Signing>()),
            .key_management = testing::NiceMock<MockKeyManagement>(
                default_backend_->Get<KeyManagement>()),
            .session_management = testing::NiceMock<MockSessionManagement>(
                default_backend_->Get<SessionManagement>()),
            .config =
                testing::NiceMock<MockConfig>(default_backend_->Get<Config>()),
            .random =
                testing::NiceMock<MockRandom>(default_backend_->Get<Random>()),
            .pinweaver = testing::NiceMock<MockPinWeaver>(
                default_backend_->Get<PinWeaver>()),
            .vendor =
                testing::NiceMock<MockVendor>(default_backend_->Get<Vendor>()),
            .recovery_crypto = testing::NiceMock<MockRecoveryCrypto>(
                default_backend_->Get<RecoveryCrypto>()),
            .u2f = testing::NiceMock<MockU2f>(default_backend_->Get<U2f>()),
            .attestation = testing::NiceMock<MockAttestation>(
                default_backend_->Get<Attestation>()),
            .version_attestation = testing::NiceMock<MockVersionAttestation>(
                default_backend_->Get<VersionAttestation>()),
        }) {}

  ~MockBackend() override = default;

  MockBackendData& GetMock() { return mock_data_; }

 private:
  State* GetState() override { return &mock_data_.state; }
  DAMitigation* GetDAMitigation() override { return &mock_data_.da_mitigation; }
  Storage* GetStorage() override { return &mock_data_.storage; }
  RoData* GetRoData() override { return &mock_data_.ro_data; }
  Sealing* GetSealing() override { return &mock_data_.sealing; }
  SignatureSealing* GetSignatureSealing() override {
    return &mock_data_.signature_sealing;
  }
  Deriving* GetDeriving() override { return &mock_data_.deriving; }
  Encryption* GetEncryption() override { return &mock_data_.encryption; }
  Signing* GetSigning() override { return &mock_data_.signing; }
  KeyManagement* GetKeyManagement() override {
    return &mock_data_.key_management;
  }
  SessionManagement* GetSessionManagement() override {
    return &mock_data_.session_management;
  }
  Config* GetConfig() override { return &mock_data_.config; }
  Random* GetRandom() override { return &mock_data_.random; }
  PinWeaver* GetPinWeaver() override { return &mock_data_.pinweaver; }
  Vendor* GetVendor() override { return &mock_data_.vendor; }
  RecoveryCrypto* GetRecoveryCrypto() override {
    return &mock_data_.recovery_crypto;
  }
  U2f* GetU2f() override { return &mock_data_.u2f; }
  Attestation* GetAttestation() override { return &mock_data_.attestation; }
  VersionAttestation* GetVersionAttestation() override {
    return &mock_data_.version_attestation;
  }

  std::unique_ptr<Backend> default_backend_;
  MockBackendData mock_data_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_BACKEND_H_
