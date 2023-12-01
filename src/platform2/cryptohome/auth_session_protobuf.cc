// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_protobuf.h"

#include <optional>

#include <base/logging.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_intent.h"

namespace cryptohome {

user_data_auth::AuthIntent AuthIntentToProto(AuthIntent auth_intent) {
  switch (auth_intent) {
    case AuthIntent::kDecrypt:
      return user_data_auth::AUTH_INTENT_DECRYPT;
    case AuthIntent::kVerifyOnly:
      return user_data_auth::AUTH_INTENT_VERIFY_ONLY;
    case AuthIntent::kWebAuthn:
      return user_data_auth::AUTH_INTENT_WEBAUTHN;
  }
}

std::optional<AuthIntent> AuthIntentFromProto(
    user_data_auth::AuthIntent auth_intent) {
  switch (auth_intent) {
    case user_data_auth::AUTH_INTENT_DECRYPT:
      return AuthIntent::kDecrypt;
    case user_data_auth::AUTH_INTENT_VERIFY_ONLY:
      return AuthIntent::kVerifyOnly;
    case user_data_auth::AUTH_INTENT_WEBAUTHN:
      return AuthIntent::kWebAuthn;
    default:
      LOG(WARNING) << "Unknown AuthIntent " << auth_intent;
      return std::nullopt;
  }
}

}  // namespace cryptohome
