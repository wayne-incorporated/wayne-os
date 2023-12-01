// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_SESSION_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_TPM2_SESSION_MANAGEMENT_H_

#include <functional>
#include <memory>

#include <absl/container/flat_hash_map.h>
#include <trunks/hmac_session.h>

#include "libhwsec/backend/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

enum class SessionSecuritySetting {
  // The command content can be viewed by the passive attacker.
  kNoEncrypted,
  // The command content can be viewed by the passive attacker if they know the
  // auth value that is set by SetEntityAuthorizationValue.
  kEncrypted,
  // The command content cannot be viewed by the passive attacker.
  kSaltAndEncrypted,
};

struct SessionSecurityDetail {
  NoDefault<bool> salted;
  NoDefault<bool> enable_encryption;
};

inline SessionSecurityDetail ToSessionSecurityDetail(
    SessionSecuritySetting setting) {
  switch (setting) {
    case SessionSecuritySetting::kNoEncrypted:
      return SessionSecurityDetail{
          .salted = false,
          .enable_encryption = false,
      };
    case SessionSecuritySetting::kEncrypted:
      return SessionSecurityDetail{
          .salted = false,
          .enable_encryption = true,
      };
    case SessionSecuritySetting::kSaltAndEncrypted:
      return SessionSecurityDetail{
          .salted = true,
          .enable_encryption = true,
      };
  }
}

class SessionManagementTpm2 : public SessionManagement {
 public:
  explicit SessionManagementTpm2(TrunksContext& context) : context_(context) {}

  Status FlushInvalidSessions() override;

  // Get the reference for existing unbound hmac session or create a new unbound
  // session if it doesn't exist.
  StatusOr<std::reference_wrapper<trunks::HmacSession>> GetOrCreateHmacSession(
      SessionSecuritySetting setting);

 private:
  TrunksContext& context_;

  absl::flat_hash_map<SessionSecuritySetting,
                      std::unique_ptr<trunks::HmacSession>>
      hmac_sessions_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_SESSION_MANAGEMENT_H_
