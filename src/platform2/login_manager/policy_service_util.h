// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_POLICY_SERVICE_UTIL_H_
#define LOGIN_MANAGER_POLICY_SERVICE_UTIL_H_

#include <string>

#include <base/types/expected.h>

#include "bindings/device_management_backend.pb.h"
#include "crypto/signature_verifier.h"

namespace login_manager {
// Maps signature types defined in em::PolicyFetchRequest proto
// to signature types in crypto::SignatureVerifier.
// Returns error if em::PolicyFetchRequest::NONE is passed.
base::expected<crypto::SignatureVerifier::SignatureAlgorithm, std::string>
MapSignatureType(const enterprise_management::PolicyFetchRequest::SignatureType
                     signature_type);

}  // namespace login_manager

#endif  // LOGIN_MANAGER_POLICY_SERVICE_UTIL_H_
