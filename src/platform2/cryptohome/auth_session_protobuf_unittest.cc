// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_protobuf.h"

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>

#include "cryptohome/auth_session.h"

namespace cryptohome {

TEST(AuthSessionProtoUtils, AuthIntentToProto) {
  EXPECT_EQ(AuthIntentToProto(AuthIntent::kDecrypt),
            user_data_auth::AUTH_INTENT_DECRYPT);
  EXPECT_EQ(AuthIntentToProto(AuthIntent::kVerifyOnly),
            user_data_auth::AUTH_INTENT_VERIFY_ONLY);
}

}  // namespace cryptohome
