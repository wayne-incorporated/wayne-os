// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/hmac_session_impl.h"

#include <string>

#include <base/logging.h>
#include <base/stl_util.h>
#include <openssl/rand.h>

namespace trunks {

HmacSessionImpl::HmacSessionImpl(const TrunksFactory& factory)
    : factory_(factory) {
  session_manager_ = factory_.GetSessionManager();
}

HmacSessionImpl::~HmacSessionImpl() {
  session_manager_->CloseSession();
}

AuthorizationDelegate* HmacSessionImpl::GetDelegate() {
  if (session_manager_->GetSessionHandle() == kUninitializedHandle) {
    return nullptr;
  }
  return &hmac_delegate_;
}

TPM_RC HmacSessionImpl::StartBoundSession(
    TPMI_DH_ENTITY bind_entity,
    const std::string& bind_authorization_value,
    bool salted,
    bool enable_encryption) {
  return session_manager_->StartSession(TPM_SE_HMAC, bind_entity,
                                        bind_authorization_value, salted,
                                        enable_encryption, &hmac_delegate_);
}

TPM_RC HmacSessionImpl::StartUnboundSession(bool salted,
                                            bool enable_encryption) {
  // Starting an unbound session is the same as starting a session bound to
  // TPM_RH_NULL. In this case, the authorization is the zero length buffer.
  // We can therefore simply call StartBoundSession with TPM_RH_NULL as the
  // binding entity, and the empty string as the authorization.
  return StartBoundSession(TPM_RH_NULL, "", salted, enable_encryption);
}

void HmacSessionImpl::SetEntityAuthorizationValue(const std::string& value) {
  hmac_delegate_.set_entity_authorization_value(value);
}

void HmacSessionImpl::SetFutureAuthorizationValue(const std::string& value) {
  hmac_delegate_.set_future_authorization_value(value);
}

}  // namespace trunks
