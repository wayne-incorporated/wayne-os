// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_flatbuffer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/auth_intent.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {
namespace {

using ::testing::Eq;

TEST(SerializeAuthIntent, TypeConversionIsInvertable) {
  // Test a round trip of all of the values.
  EXPECT_THAT(DeserializeAuthIntent(SerializeAuthIntent(AuthIntent::kDecrypt)),
              Eq(AuthIntent::kDecrypt));
  EXPECT_THAT(
      DeserializeAuthIntent(SerializeAuthIntent(AuthIntent::kVerifyOnly)),
      Eq(AuthIntent::kVerifyOnly));
  EXPECT_THAT(DeserializeAuthIntent(SerializeAuthIntent(AuthIntent::kWebAuthn)),
              Eq(AuthIntent::kWebAuthn));
}

}  // namespace
}  // namespace cryptohome
