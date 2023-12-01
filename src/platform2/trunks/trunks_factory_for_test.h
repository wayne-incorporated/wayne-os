// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_FACTORY_FOR_TEST_H_
#define TRUNKS_TRUNKS_FACTORY_FOR_TEST_H_

#include "trunks/trunks_factory.h"

#include <memory>
#include <string>
#include <vector>

#include "trunks/password_authorization_delegate.h"
#include "trunks/trunks_export.h"

namespace trunks {

class AuthorizationDelegate;
class MockBlobParser;
class MockHmacSession;
class MockPolicySession;
class MockSessionManager;
class MockTpm;
class MockTpmCache;
class MockTpmState;
class MockTpmUtility;
class HmacSession;
class PasswordAuthorizationDelegate;
class PolicySession;
class SessionManager;
class Tpm;
class TpmCache;
class TpmState;
class TpmUtility;

// A factory implementation for testing. Custom instances can be injected. If no
// instance has been injected, a default mock instance will be used. Objects for
// which ownership is passed to the caller are instantiated as forwarders which
// simply forward calls to the current instance set for the class.
//
// Example usage:
//   TrunksFactoryForTest factory;
//   MockTpmState mock_tpm_state;
//   factory.set_tpm_state(mock_tpm_state);
//   // Set expectations on mock_tpm_state...
class TRUNKS_EXPORT TrunksFactoryForTest : public TrunksFactory {
 public:
  TrunksFactoryForTest();
  TrunksFactoryForTest(const TrunksFactoryForTest&) = delete;
  TrunksFactoryForTest& operator=(const TrunksFactoryForTest&) = delete;

  ~TrunksFactoryForTest() override;

  // TrunksFactory methods.
  Tpm* GetTpm() const override;
  TpmCache* GetTpmCache() const override;
  std::unique_ptr<TpmState> GetTpmState() const override;
  std::unique_ptr<TpmUtility> GetTpmUtility() const override;
  std::unique_ptr<AuthorizationDelegate> GetPasswordAuthorization(
      const std::string& password) const override;
  std::unique_ptr<SessionManager> GetSessionManager() const override;
  std::unique_ptr<HmacSession> GetHmacSession() const override;
  std::unique_ptr<PolicySession> GetPolicySession() const override;
  std::unique_ptr<PolicySession> GetTrialSession() const override;
  std::unique_ptr<BlobParser> GetBlobParser() const override;

  // Mutators to inject custom mocks.
  void set_tpm(Tpm* tpm) { tpm_ = tpm; }

  void set_tpm_cache(TpmCache* tpm_cache) { tpm_cache_ = tpm_cache; }

  void set_tpm_state(TpmState* tpm_state) { tpm_state_ = tpm_state; }

  void set_tpm_utility(TpmUtility* tpm_utility) { tpm_utility_ = tpm_utility; }

  void set_used_password(std::vector<std::string>* buf) {
    used_password_ = buf;
  }

  void set_password_authorization_delegate(AuthorizationDelegate* delegate) {
    password_authorization_delegate_ = delegate;
  }

  void set_session_manager(SessionManager* session_manager) {
    session_manager_ = session_manager;
  }

  void set_hmac_session(HmacSession* hmac_session) {
    hmac_session_ = hmac_session;
  }

  void set_policy_session(PolicySession* policy_session) {
    policy_session_ = policy_session;
  }

  void set_trial_session(PolicySession* trial_session) {
    trial_session_ = trial_session;
  }

  void set_blob_parser(BlobParser* blob_parser) { blob_parser_ = blob_parser; }

 private:
  std::unique_ptr<MockTpm> default_tpm_;
  Tpm* tpm_;
  std::unique_ptr<MockTpmCache> default_tpm_cache_;
  TpmCache* tpm_cache_;
  std::unique_ptr<MockTpmState> default_tpm_state_;
  TpmState* tpm_state_;
  std::unique_ptr<MockTpmUtility> default_tpm_utility_;
  TpmUtility* tpm_utility_;
  std::vector<std::string>* used_password_;
  std::unique_ptr<PasswordAuthorizationDelegate>
      default_authorization_delegate_;
  AuthorizationDelegate* password_authorization_delegate_;
  std::unique_ptr<MockSessionManager> default_session_manager_;
  SessionManager* session_manager_;
  std::unique_ptr<MockHmacSession> default_hmac_session_;
  HmacSession* hmac_session_;
  std::unique_ptr<MockPolicySession> default_policy_session_;
  PolicySession* policy_session_;
  std::unique_ptr<MockPolicySession> default_trial_session_;
  PolicySession* trial_session_;
  std::unique_ptr<MockBlobParser> default_blob_parser_;
  BlobParser* blob_parser_;
};

}  // namespace trunks

#endif  // TRUNKS_TRUNKS_FACTORY_FOR_TEST_H_
