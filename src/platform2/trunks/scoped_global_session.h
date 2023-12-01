// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_SCOPED_GLOBAL_SESSION_H_
#define TRUNKS_SCOPED_GLOBAL_SESSION_H_

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/error_codes.h"
#include "trunks/hmac_session.h"
#include "trunks/trunks_factory.h"

namespace trunks {

// TODO(http://crbug.com/473843): restore using one global session without
// restarting, when session handles virtualization is supported by trunks.
#define TRUNKS_USE_PER_OP_SESSIONS

// Helper class for handling global HMAC sessions. Until resource manager
// supports handles virtualization, global sessions should not be used:
// a session handle may be flushed after a system is suspended.
// To support cases when daemons create a global session as
// std::unique_ptr<HmacSession> during initialization and then reuse it over
// the lifetime of the daemon, each operation that calls such |global_session_|
// should before use define a scoped hmac session variable:
// ScopedGlobalHmacSession(<factory-ptr>, <enable-encryption>, &global_session_)
#ifdef TRUNKS_USE_PER_OP_SESSIONS
class ScopedGlobalHmacSession {
 public:
  ScopedGlobalHmacSession(const TrunksFactory* factory,
                          bool salted,
                          bool enable_encryption,
                          std::unique_ptr<HmacSession>* session)
      : target_session_(session) {
    DCHECK(target_session_);
    VLOG_IF(1, *target_session_) << "Concurrent sessions?";
    std::unique_ptr<HmacSession> new_session = factory->GetHmacSession();
    TPM_RC result = new_session->StartUnboundSession(salted, enable_encryption);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << "Error starting an authorization session: "
                 << GetErrorString(result);
      *target_session_ = nullptr;
    } else {
      *target_session_ = std::move(new_session);
    }
  }
  ScopedGlobalHmacSession(const ScopedGlobalHmacSession&) = delete;
  ScopedGlobalHmacSession& operator=(const ScopedGlobalHmacSession&) = delete;

  ~ScopedGlobalHmacSession() { *target_session_ = nullptr; }

 private:
  std::unique_ptr<HmacSession>* target_session_;
};
#else  // TRUNKS_USE_PER_OP_SESSIONS
class ScopedGlobalHmacSession {
 public:
  ScopedGlobalHmacSession(const TrunksFactory* /* factory */,
                          bool /* salted */,
                          bool /* enable_encryption */,
                          std::unique_ptr<HmacSession>* /* session */) {}
  ScopedGlobalHmacSession(const ScopedGlobalHmacSession&) = delete;
  ScopedGlobalHmacSession& operator=(const ScopedGlobalHmacSession&) = delete;
};
#endif  // TRUNKS_USE_PER_OP_SESSIONS

}  // namespace trunks

#endif  // TRUNKS_SCOPED_GLOBAL_SESSION_H_
