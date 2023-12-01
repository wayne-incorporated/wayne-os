// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_UTILS_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_UTILS_H_

#include <map>
#include <memory>
#include <optional>
#include <string>

#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <google/protobuf/repeated_field.h>

#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/auth_factor/auth_factor_map.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_prepare_purpose.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/manager.h"
#include "cryptohome/auth_factor_vault_keyset_converter.h"
#include "cryptohome/crypto.h"
#include "cryptohome/features.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Populates any relevant fields in an AuthFactor proto with the relevant system
// information (e.g. OS version). Will overwrite any info already populating the
// system information fields, but will not touch any other fields.
void PopulateAuthFactorProtoWithSysinfo(
    user_data_auth::AuthFactor& auth_factor);

// GetAuthFactorMetadata sets the metadata inferred from the proto. This
// includes the metadata struct, type and label.
bool GetAuthFactorMetadata(const user_data_auth::AuthFactor& auth_factor,
                           const AsyncInitFeatures& feature_lib,
                           AuthFactorMetadata& out_auth_factor_metadata,
                           AuthFactorType& out_auth_factor_type,
                           std::string& out_auth_factor_label);

// Gets AuthFactor for a given user and label. Returns false if the
// corresponding AuthFactor does not exist.
bool LoadUserAuthFactorByLabel(AuthFactorDriverManager* driver_manager,
                               AuthFactorManager* manager,
                               const AuthBlockUtility& auth_block_utility,
                               const ObfuscatedUsername& obfuscated_username,
                               const std::string& factor_label,
                               user_data_auth::AuthFactor* out_auth_factor);

// Converts to AuthFactorPreparePurpose from the proto enum.
std::optional<AuthFactorPreparePurpose> AuthFactorPreparePurposeFromProto(
    user_data_auth::AuthFactorPreparePurpose purpose);

// Given a keyset converter, factor manager, and platform, load all of the auth
// factors for the given user into an auth factor.
AuthFactorMap LoadAuthFactorMap(bool is_uss_migration_enabled,
                                const ObfuscatedUsername& obfuscated_username,
                                Platform& platform,
                                AuthFactorVaultKeysetConverter& converter,
                                AuthFactorManager& manager);

}  // namespace cryptohome
#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_UTILS_H_
