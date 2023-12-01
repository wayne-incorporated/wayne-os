// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_service_util.h"

#include <string>

#include <base/types/expected.h>

#include "bindings/device_management_backend.pb.h"
#include "crypto/signature_verifier.h"

namespace em = enterprise_management;

namespace login_manager {

base::expected<crypto::SignatureVerifier::SignatureAlgorithm, std::string>
MapSignatureType(const em::PolicyFetchRequest::SignatureType signature_type) {
  switch (signature_type) {
    case em::PolicyFetchRequest::SHA256_RSA:
      return crypto::SignatureVerifier::RSA_PKCS1_SHA256;
    case em::PolicyFetchRequest::SHA1_RSA:
      return crypto::SignatureVerifier::RSA_PKCS1_SHA1;
    default:
      return base::unexpected("Bad argument");
  }
}
}  // namespace login_manager
