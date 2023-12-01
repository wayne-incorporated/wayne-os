// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_FLATBUFFER_H_
#define CRYPTOHOME_AUTH_FACTOR_FLATBUFFER_H_

#include <optional>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {

// Convert AuthFactorType to and from the serialized flatbuffer type.
std::optional<enumeration::SerializedAuthFactorType> SerializeAuthFactorType(
    AuthFactorType type);
AuthFactorType DeserializeAuthFactorType(
    enumeration::SerializedAuthFactorType type);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_FLATBUFFER_H_
