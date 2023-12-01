// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_SESSION_PROTOBUF_H_
#define CRYPTOHOME_AUTH_SESSION_PROTOBUF_H_

#include <optional>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_session.h"

namespace cryptohome {

user_data_auth::AuthIntent AuthIntentToProto(AuthIntent auth_intent);
std::optional<AuthIntent> AuthIntentFromProto(
    user_data_auth::AuthIntent auth_intent);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_SESSION_PROTOBUF_H_
