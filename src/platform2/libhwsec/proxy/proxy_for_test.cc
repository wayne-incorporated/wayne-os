// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/proxy/proxy_for_test.h"

#include <memory>

#include <libcrossystem/crossystem.h>
#include <libcrossystem/crossystem_fake.h>
#include <gmock/gmock.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#if USE_TPM2

// Prevent the conflict definition from tss.h
#pragma push_macro("TPM_ALG_RSA")
#undef TPM_ALG_RSA
#pragma push_macro("TPM_ALG_SHA")
#undef TPM_ALG_SHA
#pragma push_macro("TPM_ALG_HMAC")
#undef TPM_ALG_HMAC
#pragma push_macro("TPM_ALG_AES")
#undef TPM_ALG_AES
#pragma push_macro("TPM_ALG_MGF1")
#undef TPM_ALG_MGF1
#pragma push_macro("TPM_ALG_XOR")
#undef TPM_ALG_XOR

#include <trunks/mock_authorization_delegate.h>
#include <trunks/mock_blob_parser.h>
#include <trunks/mock_command_transceiver.h>
#include <trunks/mock_hmac_session.h>
#include <trunks/mock_policy_session.h>
#include <trunks/mock_tpm.h>
#include <trunks/mock_tpm_cache.h>
#include <trunks/mock_tpm_state.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/trunks_factory_for_test.h>

// Restore the definitions
#pragma pop_macro("TPM_ALG_RSA")
#pragma pop_macro("TPM_ALG_SHA")
#pragma pop_macro("TPM_ALG_HMAC")
#pragma pop_macro("TPM_ALG_AES")
#pragma pop_macro("TPM_ALG_MGF1")
#pragma pop_macro("TPM_ALG_XOR")

#endif

#if USE_TPM1
#include "libhwsec/overalls/mock_overalls.h"
#endif

#include "libhwsec/platform/fake_platform.h"
#include "libhwsec/proxy/proxy.h"

namespace hwsec {

struct ProxyForTest::InnerData {
#if USE_TPM1
  testing::NiceMock<hwsec::overalls::MockOveralls> overalls;
#endif  // USE_TPM1
#if USE_TPM2
  testing::NiceMock<trunks::MockCommandTransceiver> trunks_command_transceiver;
  testing::NiceMock<trunks::MockTpm> tpm;
  testing::NiceMock<trunks::MockTpmCache> tpm_cache;
  testing::NiceMock<trunks::MockTpmState> tpm_state;
  testing::NiceMock<trunks::MockTpmUtility> tpm_utility;
  testing::NiceMock<trunks::MockAuthorizationDelegate> authorization_delegate;
  testing::NiceMock<trunks::MockHmacSession> hmac_session;
  testing::NiceMock<trunks::MockPolicySession> policy_session;
  testing::NiceMock<trunks::MockPolicySession> trial_session;
  testing::NiceMock<trunks::MockBlobParser> blob_parser;
  trunks::TrunksFactoryForTest trunks_factory;
#endif  // USE_TPM2
  testing::NiceMock<org::chromium::TpmManagerProxyMock> tpm_manager;
  testing::NiceMock<org::chromium::TpmNvramProxyMock> tpm_nvram;
  crossystem::Crossystem crossystem{
      std::make_unique<crossystem::fake::CrossystemFake>()};
  testing::NiceMock<FakePlatform> platform;
};

ProxyForTest::ProxyForTest()
    : inner_data_(std::make_unique<ProxyForTest::InnerData>()) {
#if USE_TPM1
  SetOveralls(&inner_data_->overalls);
#endif
#if USE_TPM2
  trunks::TrunksFactoryForTest& factory = inner_data_->trunks_factory;
  factory.set_tpm(&inner_data_->tpm);
  factory.set_tpm_cache(&inner_data_->tpm_cache);
  factory.set_tpm_state(&inner_data_->tpm_state);
  factory.set_tpm_utility(&inner_data_->tpm_utility);
  factory.set_password_authorization_delegate(
      &inner_data_->authorization_delegate);
  factory.set_hmac_session(&inner_data_->hmac_session);
  factory.set_policy_session(&inner_data_->policy_session);
  factory.set_trial_session(&inner_data_->trial_session);
  factory.set_blob_parser(&inner_data_->blob_parser);
  SetTrunksCommandTransceiver(&inner_data_->trunks_command_transceiver);
  SetTrunksFactory(&inner_data_->trunks_factory);
#endif
  SetTpmManager(&inner_data_->tpm_manager);
  SetTpmNvram(&inner_data_->tpm_nvram);
  SetCrossystem(&inner_data_->crossystem);
  SetPlatform(&inner_data_->platform);
}

ProxyForTest::~ProxyForTest() = default;

#if USE_TPM1

hwsec::overalls::MockOveralls& ProxyForTest::GetMockOveralls() {
  return inner_data_->overalls;
}

#endif  // USE_TPM1

#if USE_TPM2

trunks::MockCommandTransceiver& ProxyForTest::GetMockCommandTransceiver() {
  return inner_data_->trunks_command_transceiver;
}

trunks::MockTpm& ProxyForTest::GetMockTpm() {
  return inner_data_->tpm;
}

trunks::MockTpmCache& ProxyForTest::GetMockTpmCache() {
  return inner_data_->tpm_cache;
}

trunks::MockTpmState& ProxyForTest::GetMockTpmState() {
  return inner_data_->tpm_state;
}

trunks::MockTpmUtility& ProxyForTest::GetMockTpmUtility() {
  return inner_data_->tpm_utility;
}

trunks::MockAuthorizationDelegate&
ProxyForTest::GetMockAuthorizationDelegate() {
  return inner_data_->authorization_delegate;
}

trunks::MockHmacSession& ProxyForTest::GetMockHmacSession() {
  return inner_data_->hmac_session;
}

trunks::MockPolicySession& ProxyForTest::GetMockPolicySession() {
  return inner_data_->policy_session;
}

trunks::MockPolicySession& ProxyForTest::GetMockTrialSession() {
  return inner_data_->trial_session;
}

trunks::MockBlobParser& ProxyForTest::GetMockBlobParser() {
  return inner_data_->blob_parser;
}

#endif  // USE_TPM2

org::chromium::TpmManagerProxyMock& ProxyForTest::GetMockTpmManagerProxy() {
  return inner_data_->tpm_manager;
}

org::chromium::TpmNvramProxyMock& ProxyForTest::GetMockTpmNvramProxy() {
  return inner_data_->tpm_nvram;
}

crossystem::Crossystem& ProxyForTest::GetFakeCrossystem() {
  return inner_data_->crossystem;
}

FakePlatform& ProxyForTest::GetFakePlatform() {
  return inner_data_->platform;
}

}  // namespace hwsec
