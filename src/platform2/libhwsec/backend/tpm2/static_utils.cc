// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/static_utils.h"

#include <string>

#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <trunks/tpm_generated.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

template <typename OpenSSLType, auto openssl_func>
StatusOr<std::string> OpenSSLObjectToString(OpenSSLType* object) {
  if (object == nullptr) {
    return MakeStatus<TPMError>("Object is null", TPMRetryAction::kNoRetry);
  }

  unsigned char* openssl_buffer = nullptr;
  int size = openssl_func(object, &openssl_buffer);
  if (size < 0) {
    return MakeStatus<TPMError>("Failed to call openssl_func",
                                TPMRetryAction::kNoRetry);
  }
  crypto::ScopedOpenSSLBytes scoped_buffer(openssl_buffer);

  return std::string(openssl_buffer, openssl_buffer + size);
}

StatusOr<crypto::ScopedBIGNUM> StringToBignum(const std::string& big_integer) {
  if (big_integer.empty()) {
    return MakeStatus<TPMError>("Input string is empty",
                                TPMRetryAction::kNoRetry);
  }

  crypto::ScopedBIGNUM bn(BN_new());
  if (!bn) {
    return MakeStatus<TPMError>("Failed to allocate BIGNUM",
                                TPMRetryAction::kNoRetry);
  }
  if (!BN_bin2bn(reinterpret_cast<const uint8_t*>(big_integer.data()),
                 big_integer.length(), bn.get())) {
    return MakeStatus<TPMError>("Failed to convert string to BIGNUM",
                                TPMRetryAction::kNoRetry);
  }
  return bn;
}

StatusOr<crypto::ScopedECDSA_SIG> CreateEcdsaSigFromRS(const std::string& r,
                                                       const std::string& s) {
  ASSIGN_OR_RETURN(crypto::ScopedBIGNUM r_bn, StringToBignum(r));
  ASSIGN_OR_RETURN(crypto::ScopedBIGNUM s_bn, StringToBignum(s));

  crypto::ScopedECDSA_SIG sig(ECDSA_SIG_new());
  if (!sig) {
    return MakeStatus<TPMError>("Failed to allocate ECDSA",
                                TPMRetryAction::kNoRetry);
  }
  if (!ECDSA_SIG_set0(sig.get(), r_bn.release(), s_bn.release())) {
    return MakeStatus<TPMError>("Failed to set ECDSA SIG parameters",
                                TPMRetryAction::kNoRetry);
  }
  return sig;
}

}  // namespace

StatusOr<std::string> SerializeFromTpmSignature(
    const trunks::TPMT_SIGNATURE& signature) {
  switch (signature.sig_alg) {
    case trunks::TPM_ALG_RSASSA:
      if (signature.signature.rsassa.sig.size >
          sizeof(signature.signature.rsassa.sig.buffer)) {
        return MakeStatus<TPMError>("RSASSA signature overflow",
                                    TPMRetryAction::kNoRetry);
      }
      return StringFrom_TPM2B_PUBLIC_KEY_RSA(signature.signature.rsassa.sig);
    case trunks::TPM_ALG_ECDSA: {
      if (signature.signature.ecdsa.signature_r.size >
              sizeof(signature.signature.ecdsa.signature_r.buffer) ||
          signature.signature.ecdsa.signature_s.size >
              sizeof(signature.signature.ecdsa.signature_s.buffer)) {
        return MakeStatus<TPMError>("ECDSA signature overflow",
                                    TPMRetryAction::kNoRetry);
      }
      ASSIGN_OR_RETURN(
          crypto::ScopedECDSA_SIG sig,
          CreateEcdsaSigFromRS(StringFrom_TPM2B_ECC_PARAMETER(
                                   signature.signature.ecdsa.signature_r),
                               StringFrom_TPM2B_ECC_PARAMETER(
                                   signature.signature.ecdsa.signature_s)),
          _.WithStatus<TPMError>("Failed to create ECDSA SIG"));
      return OpenSSLObjectToString<ECDSA_SIG, i2d_ECDSA_SIG>(sig.get());
    }
    default:
      return MakeStatus<TPMError>("Unkown TPM 2.0 signature type",
                                  TPMRetryAction::kNoRetry);
  }
}

}  // namespace hwsec
