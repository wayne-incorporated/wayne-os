// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_flatbuffer.h"

#include "cryptohome/auth_intent.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {

enumeration::SerializedAuthIntent SerializeAuthIntent(AuthIntent intent) {
  switch (intent) {
    case AuthIntent::kDecrypt:
      return enumeration::SerializedAuthIntent::kDecrypt;
    case AuthIntent::kVerifyOnly:
      return enumeration::SerializedAuthIntent::kVerifyOnly;
    case AuthIntent::kWebAuthn:
      return enumeration::SerializedAuthIntent::kWebAuthn;
  }
}

AuthIntent DeserializeAuthIntent(enumeration::SerializedAuthIntent intent) {
  switch (intent) {
    case enumeration::SerializedAuthIntent::kDecrypt:
      return AuthIntent::kDecrypt;
    case enumeration::SerializedAuthIntent::kVerifyOnly:
      return AuthIntent::kVerifyOnly;
    case enumeration::SerializedAuthIntent::kWebAuthn:
      return AuthIntent::kWebAuthn;
  }
}

}  // namespace cryptohome
