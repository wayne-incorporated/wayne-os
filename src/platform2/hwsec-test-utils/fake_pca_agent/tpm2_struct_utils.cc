// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/tpm2_struct_utils.h"

#include <string>

#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>

#include "hwsec-test-utils/common/openssl_utility.h"

#include <base/check_op.h>
#include <base/logging.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

namespace {

constexpr int kWellKnownExponent = 65537;

crypto::ScopedBIGNUM StringToBignum(const std::string& s) {
  crypto::ScopedBIGNUM bn(BN_bin2bn(
      reinterpret_cast<const unsigned char*>(s.data()), s.length(), nullptr));
  if (!bn) {
    LOG(ERROR) << __func__
               << ": Failed to call BN_bin2bn: " << GetOpenSSLError();
    return nullptr;
  }
  return bn;
}

crypto::ScopedEVP_PKEY TpmtPublicToRsaKey(
    const trunks::TPMT_PUBLIC& tpmt_public) {
  CHECK_EQ(tpmt_public.type, trunks::TPM_ALG_RSA);

  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!rsa || !e) {
    LOG(ERROR) << __func__
               << ": Failed to allocate RSA or BIGNUMs: " << GetOpenSSLError();
    return nullptr;
  }

  if (BN_set_word(e.get(), kWellKnownExponent) != 1) {
    LOG(ERROR) << __func__ << ": Failed to create BIGNUM of exponent: "
               << GetOpenSSLError();
    return nullptr;
  }

  crypto::ScopedBIGNUM n = StringToBignum(
      trunks::StringFrom_TPM2B_PUBLIC_KEY_RSA(tpmt_public.unique.rsa));
  if (!n) {
    LOG(ERROR) << __func__ << ": Failed to create BIGNUM of modulus.";
    return nullptr;
  }

  if (RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr) != 1) {
    LOG(ERROR) << __func__ << ": Failed to set exponent or modulus.";
    return nullptr;
  }
  crypto::ScopedEVP_PKEY key(EVP_PKEY_new());
  if (!key) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_new: " << GetOpenSSLError();
    return nullptr;
  }
  if (EVP_PKEY_set1_RSA(key.get(), rsa.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_set1_RSA: " << GetOpenSSLError();
    return nullptr;
  }
  return key;
}

crypto::ScopedEVP_PKEY TpmtPublicToECCKey(
    const trunks::TPMT_PUBLIC& tpmt_public) {
  CHECK_EQ(tpmt_public.type, trunks::TPM_ALG_ECC);

  const trunks::TPMS_ECC_PARMS& ecc_params = tpmt_public.parameters.ecc_detail;
  if (ecc_params.curve_id != trunks::TPM_ECC_NIST_P256) {
    LOG(ERROR) << __func__ << ": Unsupported curve id.";
    return nullptr;
  }
  crypto::ScopedEC_KEY ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ec_key) {
    LOG(ERROR) << __func__ << ": Failed to call EC_KEY_new_by_curve_name: "
               << GetOpenSSLError();
    return nullptr;
  }
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);

  crypto::ScopedBIGNUM x_point = StringToBignum(
      trunks::StringFrom_TPM2B_ECC_PARAMETER(tpmt_public.unique.ecc.x));
  if (!x_point) {
    LOG(ERROR) << __func__ << ": Failed to create X point.";
    return nullptr;
  }
  crypto::ScopedBIGNUM y_point = StringToBignum(
      trunks::StringFrom_TPM2B_ECC_PARAMETER(tpmt_public.unique.ecc.y));
  if (!y_point) {
    LOG(ERROR) << __func__ << ": Failed to create Y point.";
    return nullptr;
  }
  if (EC_KEY_set_public_key_affine_coordinates(ec_key.get(), x_point.get(),
                                               y_point.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EC_KEY_set_public_key_affine_coordinates: "
               << GetOpenSSLError();
    return nullptr;
  }
  if (EC_KEY_check_key(ec_key.get()) != 1) {
    LOG(ERROR) << __func__ << ": Bad ECC key (EC_KEY_check_key failed): "
               << GetOpenSSLError();
    return nullptr;
  }
  crypto::ScopedEVP_PKEY key(EVP_PKEY_new());
  if (!key) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_new: " << GetOpenSSLError();
    return nullptr;
  }
  if (EVP_PKEY_set1_EC_KEY(key.get(), ec_key.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_set1_EC_KEY: "
               << GetOpenSSLError();
    return nullptr;
  }
  return key;
}

}  // namespace

crypto::ScopedEVP_PKEY TpmtPublicToEVP(std::string serialized,
                                       std::string* name) {
  trunks::TPMT_PUBLIC parsed{};
  trunks::TPM_RC result;
  std::string value_bytes;
  if ((result = Parse_TPMT_PUBLIC(&serialized, &parsed, &value_bytes)) !=
      trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ":Failed to call Parse_TPMT_PUBLIC: "
               << trunks::GetErrorString(result);
    return nullptr;
  }
  crypto::ScopedEVP_PKEY key;
  switch (parsed.type) {
    case trunks::TPM_ALG_RSA:
      key = TpmtPublicToRsaKey(parsed);
      break;
    case trunks::TPM_ALG_ECC:
      key = TpmtPublicToECCKey(parsed);
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown key type: " << parsed.type;
      return nullptr;
  }
  if (!key) {
    LOG(ERROR) << __func__ << ": Failed to create EVP_PKEY.";
    return nullptr;
  }

  // Compute the key's name (TPM2.0 spec Part I 16 Names) if needed.
  if (name != nullptr) {
    if (parsed.name_alg != trunks::TPM_ALG_SHA256) {
      LOG(ERROR) << __func__
                 << ": Unsupported name algorithm: " << parsed.name_alg;
      return nullptr;
    }
    std::string prefix;
    // Serialize_UINT16 should always succeed.
    CHECK_EQ(trunks::Serialize_UINT16(parsed.name_alg, &prefix),
             trunks::TPM_RC_SUCCESS);
    *name = prefix + crypto::SHA256HashString(value_bytes);
  }

  return key;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
