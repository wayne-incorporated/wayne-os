// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_SIGNING_H_
#define LIBHWSEC_BACKEND_SIGNING_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/digest_algorithms.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/no_default_init.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

struct SigningOptions {
  enum class RsaPaddingScheme {
    kPkcs1v15,
    kRsassaPss,
  };

  struct PssParams {
    NoDefault<DigestAlgorithm> mgf1_algorithm;
    NoDefault<size_t> salt_length;
  };

  DigestAlgorithm digest_algorithm = DigestAlgorithm::kSha256;

  // For RSA key, the default(std::nullopt) would be kPkcs1v15.
  // For ECC key, this should be std::nullopt.
  std::optional<RsaPaddingScheme> rsa_padding_scheme;

  // The extra parameter that would only useful for kRsassaPss.
  std::optional<PssParams> pss_params;
};

// Signing provide the functions to sign and verify.
class Signing {
 public:
  // Signs the |data| with |policy| and |key|.
  virtual StatusOr<brillo::Blob> Sign(Key key,
                                      const brillo::Blob& data,
                                      const SigningOptions& options) = 0;

  // Signs the |data| with |policy| and |key| without hasing the |data|.
  virtual StatusOr<brillo::Blob> RawSign(Key key,
                                         const brillo::Blob& data,
                                         const SigningOptions& options) = 0;

  // Verifies the |signed_data| with |policy| and |key|.
  virtual Status Verify(Key key, const brillo::Blob& signed_data) = 0;

 protected:
  Signing() = default;
  ~Signing() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_SIGNING_H_
