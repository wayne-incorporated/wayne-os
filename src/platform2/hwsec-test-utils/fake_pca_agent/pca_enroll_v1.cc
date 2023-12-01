// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_enroll_v1.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <base/check_op.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/err.h>
#include <trousers/scoped_tss_type.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#include "hwsec-test-utils/common/attestation_crypto.h"
#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/fake_pca_agent/issue_certificate.h"
#include "hwsec-test-utils/fake_pca_agent/tpm1_struct_utils.h"
#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

namespace hwsec_test_utils {
namespace fake_pca_agent {

namespace {

constexpr int kExpectedPcrLength = 20;

constexpr int kAesKeySize = 32;
constexpr int kAesBlockSize = 16;

// Uses RSA_padding_add_PKCS1_OAEP_mgf1 to generate the padded data.
std::optional<std::string> OaepPaddingWithParam(
    const std::string& data,
    size_t rsa_key_size,
    const std::string& encoding_param) {
  std::unique_ptr<unsigned char[]> output(
      std::make_unique<unsigned char[]>(rsa_key_size));
  if (RSA_padding_add_PKCS1_OAEP_mgf1(
          output.get(), rsa_key_size,
          reinterpret_cast<const unsigned char*>(data.data()), data.length(),
          reinterpret_cast<const unsigned char*>(encoding_param.data()),
          encoding_param.length(), EVP_sha1(), EVP_sha1()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call RSA_padding_add_PKCS1_OAEP_mgf1: "
               << GetOpenSSLError();
    return {};
  }
  return std::string(output.get(), output.get() + rsa_key_size);
}

}  // namespace

bool PcaEnrollV1::Preprocess() {
  identity_key_ = TpmPublicKeyToEVP(request_.identity_public_key(),
                                    /*public_key_digest=*/nullptr);
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

bool PcaEnrollV1::Verify() {
  const std::vector<const attestation::Quote*> quotes = {
      &request_.pcr0_quote(), &request_.pcr1_quote()};
  // Don't early return; instead, run through all pcr quotes to get more
  // information for debugging.
  bool any_failed_check = false;
  for (int i = 0; i < quotes.size(); ++i) {
    if (!EVPDigestVerify(identity_key_, EVP_sha1(), quotes[i]->quoted_data(),
                         quotes[i]->quote())) {
      LOG(ERROR) << __func__ << "Failed to verify quote of PCR" << i << '.';
      any_failed_check = true;
    }
    if (quotes[i]->quoted_pcr_value().size() != kExpectedPcrLength) {
      LOG(ERROR) << __func__ << ": Unexpected PCR" << i
                 << " value length: " << quotes[i]->quoted_pcr_value().size();
      any_failed_check = true;

    } else {
      const std::string digest = base::SHA1HashString(
          ToPcrComposite(i, quotes[i]->quoted_pcr_value()));
      const TPM_QUOTE_INFO& tpm_quote_info =
          *reinterpret_cast<const TPM_QUOTE_INFO*>(
              quotes[i]->quoted_data().data());
      if (memcmp(&tpm_quote_info.fixed, "QUOT", sizeof(tpm_quote_info.fixed)) !=
          0) {
        LOG(ERROR) << __func__ << ": Mismatched 'fixed' field.";
        any_failed_check = true;
      }
      if (memcmp(digest.data(), tpm_quote_info.compositeHash.digest,
                 digest.length()) != 0) {
        LOG(ERROR) << __func__ << ": Mismatched digest for PCR" << i << ".";
        any_failed_check = true;
      }
    }
  }
  return !any_failed_check;
}

bool PcaEnrollV1::Generate() {
  std::optional<std::string> cert_der = IssueTestCertificateDer(identity_key_);
  if (!cert_der) {
    LOG(ERROR) << __func__
               << ": Failed to issue a test certificate for the identity key.";
    return false;
  }

  // Generate an AES key and IV.
  std::optional<std::string> aes_key = GetRandom(kAesKeySize);
  if (!aes_key) {
    LOG(ERROR) << __func__ << ": Failed to create aes key.";
    return false;
  }
  std::optional<std::string> iv = GetRandom(kAesBlockSize);
  if (!iv) {
    LOG(ERROR) << __func__ << ": Failed to create IV.";
    return false;
  }

  // Encrypt the certificate.
  std::optional<std::string> encrypted_cert =
      EVPAesEncrypt(*cert_der, EVP_aes_256_cbc(), *aes_key, *iv);
  if (!encrypted_cert) {
    LOG(ERROR) << __func__ << ": Failed to encrypt certificate.";
  }
  const std::string encrypted_credential = *iv + *encrypted_cert;

  // Construct |TPM_ASYM_CA_CONTENTS|.
  TPM_ASYM_CA_CONTENTS asym_ac_contents = {};
  asym_ac_contents.sessionKey.algId = TPM_ALG_AES256;
  asym_ac_contents.sessionKey.encScheme = TPM_ES_SYM_CBC_PKCS5PAD;
  asym_ac_contents.sessionKey.size = kAesKeySize;
  asym_ac_contents.sessionKey.data =
      reinterpret_cast<BYTE*>(const_cast<char*>(aes_key->data()));
  const std::string aik_public_key_digest =
      base::SHA1HashString(request_.identity_public_key());
  CHECK_EQ(sizeof(asym_ac_contents.idDigest.digest),
           aik_public_key_digest.length());
  memcpy(asym_ac_contents.idDigest.digest, aik_public_key_digest.data(),
         aik_public_key_digest.length());

  const std::string asym_ac_contents_blob = Serialize(&asym_ac_contents);

  // Encrypt the TPM_ASYM_CA_CONTENTS with the EK public key.

  // The padding scheme and parameters are defined at Part I, section 31.1.1 of
  // TPM spec part 1.
  std::optional<std::string> padded_asym_ac_contents_blob =
      OaepPaddingWithParam(asym_ac_contents_blob,
                           RSA_size(EVP_PKEY_get0_RSA(endorsement_key_.get())),
                           "TCPA");
  if (!padded_asym_ac_contents_blob) {
    LOG(ERROR) << __func__ << ": Failed to add padding.";
    return false;
  }
  std::optional<std::string> encrypted_asym_content = EVPRsaEncrypt(
      endorsement_key_, *padded_asym_ac_contents_blob, RSA_NO_PADDING);
  if (!encrypted_asym_content) {
    LOG(ERROR) << __func__ << ": Failed to encrypt TPM_ASYM_CA_CONTENTS.";
    return false;
  }

  // Construct a TPM_SYM_CA_ATTESTATION structure.
  TPM_SYM_CA_ATTESTATION sym_ca_attestation = {};
  // Only set up the credential because trousers doesn't use the algorithm
  // field.
  sym_ca_attestation.credSize = encrypted_credential.length();
  sym_ca_attestation.credential =
      reinterpret_cast<BYTE*>(const_cast<char*>(encrypted_credential.data()));

  // Last, construct the response.
  encrypted_identity_credential_ = attestation::EncryptedIdentityCredential();
  encrypted_identity_credential_->set_asym_ca_contents(*encrypted_asym_content);
  encrypted_identity_credential_->set_sym_ca_attestation(
      Serialize(&sym_ca_attestation));
  encrypted_identity_credential_->set_tpm_version(attestation::TPM_1_2);
  return true;
}

bool PcaEnrollV1::Write(attestation::AttestationEnrollmentResponse* response) {
  if (!encrypted_identity_credential_) {
    return false;
  }
  *response->mutable_encrypted_identity_credential() =
      *encrypted_identity_credential_;
  return true;
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
