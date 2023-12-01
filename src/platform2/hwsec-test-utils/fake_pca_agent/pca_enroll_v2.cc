// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_enroll_v2.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <crypto/sha2.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>

#include "hwsec-test-utils/common/attestation_crypto.h"
#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/fake_pca_agent/issue_certificate.h"
#include "hwsec-test-utils/fake_pca_agent/kdf.h"
#include "hwsec-test-utils/fake_pca_agent/tpm2_struct_utils.h"
#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

#include <base/check_op.h>
#include <base/logging.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

namespace {

constexpr int kEcPointModulusLength = 32;
constexpr int kExpectedPcrLength = 32;

std::string BignumToString(const crypto::ScopedBIGNUM& bn) {
  size_t sz = BN_num_bytes(bn.get());
  std::unique_ptr<unsigned char[]> buffer =
      std::make_unique<unsigned char[]>(sz);
  BN_bn2bin(bn.get(), buffer.get());
  return std::string(buffer.get(), buffer.get() + sz);
}

bool GetEcPointInStrings(const crypto::ScopedEVP_PKEY& key,
                         std::string* x_str,
                         std::string* y_str) {
  CHECK_EQ(EVP_PKEY_base_id(key.get()), EVP_PKEY_EC);
  crypto::ScopedEC_KEY ec_key(EVP_PKEY_get1_EC_KEY(key.get()));
  const EC_POINT* ec_point = EC_KEY_get0_public_key(ec_key.get());
  const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key.get());
  crypto::ScopedBIGNUM x(BN_new()), y(BN_new());
  if (!x || !y) {
    LOG(ERROR) << __func__ << ": Failed to call BN_new: " << GetOpenSSLError();
    return false;
  }
  if (EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, x.get(), y.get(),
                                          nullptr) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EC_POINT_get_affine_coordinates_GFp: "
               << GetOpenSSLError();
    return false;
  }
  if (x_str != nullptr) {
    *x_str = BignumToString(x);
  }
  if (y_str != nullptr) {
    *y_str = BignumToString(y);
  }
  return true;
}

std::string ToSizedEccParameter(const std::string& s) {
  CHECK_LE(s.size(), kEcPointModulusLength);
  std::string size_str;
  CHECK_EQ(trunks::Serialize_UINT16(s.size(), &size_str),
           trunks::TPM_RC_SUCCESS);
  return size_str + s;
}

// Generates an new EC key and accept the result only if X and Y of the public
// key is in 32 bytes due to cr50's limitation. In case of any error, the
// returned object contains nullptr; otherwise, |x| and |y| are set to the
// public keys of the returned ECC key.
crypto::ScopedEVP_PKEY CreateNewEcKeyWithFullSize(std::string* x,
                                                  std::string* y) {
  crypto::ScopedEVP_PKEY key = CreateNewEcKey();
  if (!key) {
    LOG(ERROR) << __func__ << ": Failed to craete an EC key.";
    return nullptr;
  }
  // Validate the size of the public key.
  if (!GetEcPointInStrings(key, x, y)) {
    LOG(ERROR) << __func__ << ": Failed to check key size.";
    return nullptr;
  }
  CHECK_LE(x->size(), kEcPointModulusLength);
  CHECK_LE(y->size(), kEcPointModulusLength);
  if (x->size() == kEcPointModulusLength &&
      y->size() == kEcPointModulusLength) {
    return key;
  }
  // Probabilistically impossible to fall into infinite loop; just invoke
  // recursive call.
  LOG(WARNING) << __func__ << ": Public key length too short; retry.";
  return CreateNewEcKeyWithFullSize(x, y);
}

}  // namespace

bool PcaEnrollV2::Preprocess() {
  identity_key_ =
      TpmtPublicToEVP(request_.identity_public_key(), &identity_key_name_);
  if (!identity_key_) {
    LOG(ERROR) << __func__ << ": Failed to parse identity key.";
    return false;
  }

  crypto::ScopedEVP_PKEY ca_encryption_key =
      well_known_key_pairs::GetCaEncryptionkey();

  std::string decrypted_data;
  attestation_crypto::ReturnStatus decrypt_status = attestation_crypto::Decrypt(
      request_.encrypted_endorsement_credential(), ca_encryption_key,
      attestation_crypto::KeyDeriverDirect(), &decrypted_data);
  if (decrypt_status != attestation_crypto::ReturnStatus::kSuccess) {
    LOG(ERROR) << __func__
               << ": Failed to decrypt serialized key info; status code: "
               << static_cast<int>(decrypt_status);
    return {};
  }

  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(decrypted_data.data());
  crypto::ScopedX509 x509(
      d2i_X509(nullptr, &asn1_ptr, decrypted_data.length()));
  if (!x509) {
    LOG(ERROR) << __func__
               << ": Failed to call d2i_X509: " << GetOpenSSLError();
    return false;
  }
  endorsement_key_.reset(X509_get_pubkey(x509.get()));
  if (!endorsement_key_) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_get_pubkey: " << GetOpenSSLError();
    return false;
  }

  return true;
}

bool PcaEnrollV2::Verify() {
  const std::vector<const attestation::Quote*> quotes = {
      &request_.pcr0_quote(), &request_.pcr1_quote()};
  // Don't early return; instead, run through all pcr quotes to get more
  // information for debugging.
  bool any_failed_check = false;
  for (int i = 0; i < quotes.size(); ++i) {
    if (!EVPDigestVerify(identity_key_, EVP_sha256(), quotes[i]->quoted_data(),
                         quotes[i]->quote())) {
      LOG(ERROR) << __func__ << "Failed to verify quote of PCR" << i << '.';
      any_failed_check = true;
    }
    if (quotes[i]->quoted_pcr_value().size() != kExpectedPcrLength) {
      LOG(ERROR) << __func__ << ": Unexpected PCR" << i
                 << " value length: " << quotes[i]->quoted_pcr_value().size();
      any_failed_check = true;
    } else {
      trunks::TPMS_ATTEST tpms_attest;
      trunks::TPM_RC result = trunks::Parse_TPMS_ATTEST(
          std::make_unique<std::string>(quotes[i]->quoted_data()).get(),
          &tpms_attest, nullptr);
      if (result != trunks::TPM_RC_SUCCESS) {
        LOG(ERROR) << __func__ << ": Failed to parse quoted data.";
        any_failed_check = true;
      } else if (tpms_attest.type != trunks::TPM_ST_ATTEST_QUOTE) {
        LOG(ERROR) << __func__ << ": Wrong attesting type.";
        any_failed_check = true;
      } else {
        // Verify PCR digest.
        if (StringFrom_TPM2B_DIGEST(tpms_attest.attested.quote.pcr_digest) !=
            crypto::SHA256HashString(quotes[i]->quoted_pcr_value())) {
          LOG(ERROR) << __func__ << ": Mismatched pcr digest.";
          any_failed_check = true;
        }
        // Verify PCR index.
        if (tpms_attest.attested.quote.pcr_select.count != 1) {
          LOG(ERROR) << __func__ << ": Mismatched pcr selection count: "
                     << tpms_attest.attested.quote.pcr_select.count;
          any_failed_check = true;
        }
        const trunks::TPMS_PCR_SELECTION& pcr_selection =
            tpms_attest.attested.quote.pcr_select.pcr_selections[0];
        if (pcr_selection.hash != trunks::TPM_ALG_SHA256) {
          LOG(ERROR) << __func__ << ": Unexpected pcr digest algorithm: "
                     << pcr_selection.hash;
          any_failed_check = true;
        }
        if (pcr_selection.sizeof_select < 1) {
          LOG(ERROR) << __func__ << ": Unexpected size_of_select: "
                     << static_cast<int>(pcr_selection.sizeof_select);
          any_failed_check = true;
        } else {
          if (pcr_selection.pcr_select[0] != (1 << i)) {
            LOG(ERROR) << __func__ << ": Unexpected pcr_select[0]: "
                       << static_cast<int>(pcr_selection.pcr_select[0]);
            any_failed_check = true;
          }
          for (int j = 1; j < pcr_selection.sizeof_select; ++j) {
            if (pcr_selection.pcr_select[j] != 0) {
              LOG(ERROR) << __func__ << ": Unexpected pcr_select[" << j << "]: "
                         << static_cast<int>(pcr_selection.pcr_select[j]);
              any_failed_check = true;
            }
          }
        }
      }
    }
  }
  return !any_failed_check;
}

bool PcaEnrollV2::Generate() {
  if (EVP_PKEY_base_id(endorsement_key_.get()) != EVP_PKEY_EC) {
    LOG(ERROR) << __func__ << ": Only ECC EK is supported.";
    return false;
  }
  std::optional<std::string> cert_der = IssueTestCertificateDer(identity_key_);
  if (!cert_der) {
    LOG(ERROR) << __func__
               << ": Failed to issue a test certificate for the identity key.";
    return false;
  }

  // Create an ephemeral key and perform ECDH.
  std::string ephemeral_x, ephemeral_y;
  crypto::ScopedEVP_PKEY ephemeral_key =
      CreateNewEcKeyWithFullSize(&ephemeral_x, &ephemeral_y);
  if (!ephemeral_key) {
    LOG(ERROR) << __func__ << ": Failed to create ephemeral key.";
    return false;
  }
  CHECK_EQ(ephemeral_x.size(), kEcPointModulusLength);
  CHECK_EQ(ephemeral_y.size(), kEcPointModulusLength);
  std::optional<std::string> z = EVPDerive(ephemeral_key, endorsement_key_);
  if (!z) {
    LOG(ERROR) << __func__ << ": Failed to create shared secret.";
    return false;
  }
  std::string tpm_static_x;
  if (!GetEcPointInStrings(endorsement_key_, &tpm_static_x,
                           /*y_str=*/nullptr)) {
    LOG(ERROR) << __func__ << ": Failed to dump endorsement key.";
    return false;
  }
  CHECK_LE(tpm_static_x.size(), 32);

  // TPM2.0 spec part I, C.8 ECC Point Padding -- Use the padded input to feed
  // DKFe.
  tpm_static_x.insert(0, 32 - tpm_static_x.size(), '\x00');

  // TPM2.0 spec Part I, 11.4.10.3 KDFe for ECDH.
  std::string ecdh_seed = KDFe(*z, "IDENTITY", ephemeral_x, tpm_static_x);
  const std::string sized_ephemeral_x = ToSizedEccParameter(ephemeral_x);
  const std::string sized_ephemeral_y = ToSizedEccParameter(ephemeral_y);

  std::optional<std::string> secret = GetRandom(32);
  if (!secret) {
    LOG(ERROR) << __func__ << ": Failed to get random secret.";
    return false;
  }
  // TPM2.0 spec Part I, 24.4 Symmetric Encryption.
  std::optional<std::string> aes_key =
      KDFa(ecdh_seed, "STORAGE", identity_key_name_, "", 128);
  if (!aes_key) {
    LOG(ERROR) << __func__ << ": Failed to derive aes key.";
    return false;
  }

  std::string serialized_secret;
  trunks::TPM2B_DIGEST tpm2b_digest;
  tpm2b_digest.size = secret->size();
  std::copy(secret->begin(), secret->end(), tpm2b_digest.buffer);
  CHECK_EQ(trunks::Serialize_TPM2B_DIGEST(tpm2b_digest, &serialized_secret),
           trunks::TPM_RC_SUCCESS);

  std::optional<std::string> encrypted_secret = EVPAesEncrypt(
      serialized_secret, EVP_aes_128_cfb(), *aes_key, std::string(16, '\x00'));
  if (!encrypted_secret) {
    LOG(ERROR) << __func__ << ": Failed to encrypt secret.";
    return false;
  }

  // TPM2.0 spec Part I, 24.5 HMAC.
  std::optional<std::string> hmac_key_str =
      KDFa(ecdh_seed, "INTEGRITY", "", "", 256);
  if (!hmac_key_str) {
    LOG(ERROR) << __func__ << ": Failed to derive hmac key.";
    return false;
  }
  crypto::ScopedEVP_PKEY hmac_key(EVP_PKEY_new_mac_key(
      EVP_PKEY_HMAC, nullptr,
      reinterpret_cast<const unsigned char*>(hmac_key_str->data()),
      hmac_key_str->length()));
  if (!hmac_key) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_new_mac_key: "
               << GetOpenSSLError();
    return false;
  }
  std::optional<std::string> encrypted_secret_hmac = EVPDigestSign(
      hmac_key, EVP_sha256(), *encrypted_secret + identity_key_name_);
  if (!encrypted_secret_hmac) {
    LOG(ERROR) << __func__
               << ": Failed to calculate HMAC for encrypted secret.";
    return false;
  }

  attestation::EncryptedData encrypted_credential;
  encrypted_credential.set_wrapped_key(*encrypted_secret);
  attestation_crypto::KeyDeriverSha256WithHeader key_deriver;
  std::optional<std::string> iv = GetRandom(16);
  if (!iv) {
    LOG(ERROR) << __func__ << ": Failed to generate IV.";
    return false;
  }
  std::optional<std::string> encrypted_cert_der = EVPAesEncrypt(
      *cert_der, EVP_aes_256_cbc(), key_deriver.ToAesKey(*secret), *iv);
  if (!encrypted_cert_der) {
    LOG(ERROR) << __func__ << ": Failed to encrypt cert.";
    return false;
  }
  const std::string encrypted_cert_der_hmac_key_str =
      key_deriver.ToHmacKey(*secret);
  crypto::ScopedEVP_PKEY encrypted_cert_der_hmac_key(
      EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                           reinterpret_cast<const unsigned char*>(
                               encrypted_cert_der_hmac_key_str.data()),
                           encrypted_cert_der_hmac_key_str.length()));
  std::optional<std::string> encrypted_cert_der_hmac = EVPDigestSign(
      encrypted_cert_der_hmac_key, EVP_sha512(), *iv + *encrypted_cert_der);
  if (!encrypted_cert_der_hmac) {
    LOG(ERROR) << __func__
               << ": Failed to calculate HMAC for encrypted certificate.";
    return false;
  }

  encrypted_credential.set_encrypted_data(*encrypted_cert_der);
  encrypted_credential.set_wrapped_key(*encrypted_secret);
  encrypted_credential.set_iv(*iv);
  encrypted_credential.set_mac(*encrypted_cert_der_hmac);

  // Last, generate the output.
  encrypted_identity_credential_ = attestation::EncryptedIdentityCredential();
  encrypted_identity_credential_->set_tpm_version(attestation::TPM_2_0);
  encrypted_identity_credential_->set_encrypted_seed(sized_ephemeral_x +
                                                     sized_ephemeral_y);
  *encrypted_identity_credential_->mutable_wrapped_certificate() =
      encrypted_credential;
  encrypted_identity_credential_->set_credential_mac(*encrypted_secret_hmac);
  return true;
}

bool PcaEnrollV2::Write(attestation::AttestationEnrollmentResponse* response) {
  if (!encrypted_identity_credential_) {
    return false;
  }
  *response->mutable_encrypted_identity_credential() =
      *encrypted_identity_credential_;
  return true;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
