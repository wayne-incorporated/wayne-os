// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_PROTOBUF_H_
#define CRYPTOHOME_AUTH_FACTOR_PROTOBUF_H_

#include <optional>

#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_factor/auth_factor_type.h"

namespace cryptohome {

// Functions to convert an auth factor type to and from the protobuf type enum.
//
// Conversion from a proto enum will only fail and return null if given a value
// that does not correspond to any enum value that was known at build time. For
// values which are known, but which can't be mapped onto any AuthFactorType
// value, the kUnspecified value will be returned.
user_data_auth::AuthFactorType AuthFactorTypeToProto(AuthFactorType type);
std::optional<AuthFactorType> AuthFactorTypeFromProto(
    user_data_auth::AuthFactorType type);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_PROTOBUF_H_
