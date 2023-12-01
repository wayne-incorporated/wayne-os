// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_FACTORY_H_
#define TRUNKS_TRUNKS_FACTORY_H_

#include <memory>
#include <string>

#include "trunks/authorization_delegate.h"
#include "trunks/blob_parser.h"
#include "trunks/hmac_session.h"
#include "trunks/policy_session.h"
#include "trunks/session_manager.h"
#include "trunks/tpm_cache.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_export.h"

namespace trunks {

class Tpm;

// TrunksFactory is an interface to act as a factory for trunks objects. This
// mechanism assists in injecting mocks for testing.
class TRUNKS_EXPORT TrunksFactory {
 public:
  TrunksFactory() {}
  TrunksFactory(const TrunksFactory&) = delete;
  TrunksFactory& operator=(const TrunksFactory&) = delete;

  virtual ~TrunksFactory() {}

  // Returns a Tpm instance. The caller does not take ownership. All calls to
  // this method on a given TrunksFactory instance will return the same value.
  virtual Tpm* GetTpm() const = 0;

  // Returns a TpmCache instance. The caller does not take ownership. All calls
  // to this method on a given TrunksFactory instance will return the same
  // value.
  virtual TpmCache* GetTpmCache() const = 0;

  // Returns an uninitialized TpmState instance. The caller takes ownership.
  virtual std::unique_ptr<TpmState> GetTpmState() const = 0;

  // Returns a TpmUtility instance. The caller takes ownership.
  virtual std::unique_ptr<TpmUtility> GetTpmUtility() const = 0;

  // Returns an AuthorizationDelegate instance for basic password authorization.
  // The caller takes ownership.
  virtual std::unique_ptr<AuthorizationDelegate> GetPasswordAuthorization(
      const std::string& password) const = 0;

  // Returns a SessionManager instance. The caller takes ownership.
  virtual std::unique_ptr<SessionManager> GetSessionManager() const = 0;

  // Returns a HmacSession instance. The caller takes ownership.
  virtual std::unique_ptr<HmacSession> GetHmacSession() const = 0;

  // Returns a PolicySession instance. The caller takes ownership.
  virtual std::unique_ptr<PolicySession> GetPolicySession() const = 0;

  // Returns a TrialSession instance. The caller takes ownership.
  virtual std::unique_ptr<PolicySession> GetTrialSession() const = 0;

  // Returns a BlobParser instance. The caller takes ownership.
  virtual std::unique_ptr<BlobParser> GetBlobParser() const = 0;
};

}  // namespace trunks

#endif  // TRUNKS_TRUNKS_FACTORY_H_
