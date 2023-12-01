// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_SESSION_FLATBUFFER_H_
#define CRYPTOHOME_AUTH_SESSION_FLATBUFFER_H_

#include "cryptohome/auth_intent.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {

// Convert AuthIntent to and from the serialized flatbuffer type.
enumeration::SerializedAuthIntent SerializeAuthIntent(AuthIntent intent);
AuthIntent DeserializeAuthIntent(enumeration::SerializedAuthIntent intent);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_SESSION_FLATBUFFER_H_
