// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_HMAC_SESSION_IMPL_H_
#define TRUNKS_HMAC_SESSION_IMPL_H_

#include "trunks/hmac_session.h"

#include <memory>
#include <string>

#include "trunks/hmac_authorization_delegate.h"
#include "trunks/session_manager.h"
#include "trunks/trunks_export.h"
#include "trunks/trunks_factory.h"

namespace trunks {

// This class implements the HmacSession interface. It is used for
// keeping track of the HmacAuthorizationDelegate used for commands, and to
// provide authorization for commands that need it. It is instantiated by
// TpmUtilityImpl. If we need to use this class outside of TpmUtility, we
// can use it as below:
// TrunksFactoryImpl factory;
// HmacSessionImpl session(factory);
// session.StartBoundSession(bind_entity, bind_authorization, true, true);
// session.SetEntityAuthorizationValue(entity_authorization);
// factory.GetTpm()->RSA_EncrpytSync(_,_,_,_, session.GetDelegate());
// NOTE: StartBoundSession/StartUnboundSession should not be called before
// TPM Ownership is taken. This is because starting a session uses the
// SaltingKey, which is only created after ownership is taken.
class TRUNKS_EXPORT HmacSessionImpl : public HmacSession {
 public:
  // The constructor for HmacAuthroizationSession needs a factory. In
  // producation code, this factory is used to access the TPM class to forward
  // commands to the TPM. In test code, this is used to mock out the TPM calls.
  explicit HmacSessionImpl(const TrunksFactory& factory);
  HmacSessionImpl(const HmacSessionImpl&) = delete;
  HmacSessionImpl& operator=(const HmacSessionImpl&) = delete;

  ~HmacSessionImpl() override;

  // HmacSession methods.
  AuthorizationDelegate* GetDelegate() override;
  TPM_RC StartBoundSession(TPMI_DH_ENTITY bind_entity,
                           const std::string& bind_authorization_value,
                           bool salted,
                           bool enable_encryption) override;
  TPM_RC StartUnboundSession(bool salted, bool enable_encryption) override;
  void SetEntityAuthorizationValue(const std::string& value) override;
  void SetFutureAuthorizationValue(const std::string& value) override;

 private:
  // This factory is only set in the constructor and is used to instantiate
  // The TPM class to forward commands to the TPM chip.
  const TrunksFactory& factory_;
  // This delegate is what provides authorization to commands. It is what is
  // returned when the GetDelegate method is called.
  HmacAuthorizationDelegate hmac_delegate_;
  // This object is used to manage the TPM session associated with this
  // HmacSession.
  std::unique_ptr<SessionManager> session_manager_;

  friend class HmacSessionTest;
};

}  // namespace trunks

#endif  // TRUNKS_HMAC_SESSION_IMPL_H_
