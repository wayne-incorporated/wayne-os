// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/tpm1_struct_utils.h"

#include <memory>
#include <optional>
#include <string>

#include <arpa/inet.h>
#include <base/check_op.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/sys_byteorder.h>
#include <crypto/scoped_openssl_types.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#include "hwsec-test-utils/common/openssl_utility.h"

#define TPM_LOG(severity, result)                               \
  LOG(severity) << "TPM error 0x" << std::hex << result << " (" \
                << Trspi_Error_String(result) << "): "

namespace hwsec_test_utils {
namespace fake_pca_agent {

namespace {

constexpr int kWellKnownExponent = 65537;
constexpr int kExpectedPcrLength = 20;

// The implementation of attestation service always selects 16 bits.
constexpr int kSelectBitmapSize = 2;

}  // namespace

crypto::ScopedEVP_PKEY TpmPublicKeyToEVP(
    const std::string& serialized_tpm_pubkey, std::string* public_key_digest) {
  // Parse the serialized TPM_PUBKEY.
  UINT64 offset = 0;
  TPM_PUBKEY parsed = {};
  TSS_RESULT result = Trspi_UnloadBlob_PUBKEY_s(
      &offset,
      reinterpret_cast<BYTE*>(const_cast<char*>(serialized_tpm_pubkey.data())),
      serialized_tpm_pubkey.length(), &parsed);
  if (result != TSS_SUCCESS) {
    TPM_LOG(ERROR, result) << "Failed to parse TPM_PUBKEY.";
    return nullptr;
  }

  // Prevent memory leak.
  std::unique_ptr<BYTE, base::FreeDeleter> scoped_key(parsed.pubKey.key);
  std::unique_ptr<BYTE, base::FreeDeleter> scoped_parms(
      parsed.algorithmParms.parms);
  if (offset != serialized_tpm_pubkey.length()) {
    LOG(ERROR) << "Found garbage data after the TPM_PUBKEY.";
    return nullptr;
  }
  TPM_RSA_KEY_PARMS parms;
  UINT64 parms_offset = 0;
  result = Trspi_UnloadBlob_RSA_KEY_PARMS_s(
      &parms_offset, parsed.algorithmParms.parms,
      parsed.algorithmParms.parmSize, &parms);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse RSA_KEY_PARMS.";
    return nullptr;
  }
  if (parms_offset != parsed.algorithmParms.parmSize) {
    LOG(ERROR) << "Find garbage data after the TPM_PUBKEY.";
    return nullptr;
  }
  std::unique_ptr<BYTE, base::FreeDeleter> scoped_exponent(parms.exponent);
  crypto::ScopedRSA rsa(RSA_new());
  if (!rsa) {
    LOG(ERROR) << "Failed to allocate RSA: " << GetOpenSSLError();
    return nullptr;
  }
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  if (!e || !n) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM.";
    return nullptr;
  }

  // Get the public exponent.
  if (parms.exponentSize == 0) {
    if (!BN_set_word(e.get(), kWellKnownExponent)) {
      LOG(ERROR) << "Failed to set exponent to WellKnownExponent.";
      return nullptr;
    }
  } else {
    if (!BN_bin2bn(parms.exponent, parms.exponentSize, e.get())) {
      LOG(ERROR) << "Failed to convert exponent to BIGNUM.";
      return nullptr;
    }
  }
  // Get the modulus.
  if (!BN_bin2bn(parsed.pubKey.key, parsed.pubKey.keyLength, n.get())) {
    LOG(ERROR) << "Failed to convert public key to BIGNUM.";
    return nullptr;
  }
  if (!RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr)) {
    LOG(ERROR) << ": Failed to set exponent or modulus.";
    return nullptr;
  }
  crypto::ScopedEVP_PKEY key(EVP_PKEY_new());
  if (!key) {
    LOG(ERROR) << ": Failed to call EVP_PKEY_new: " << GetOpenSSLError();
    return nullptr;
  }
  if (EVP_PKEY_set1_RSA(key.get(), rsa.get()) != 1) {
    LOG(ERROR) << ": Failed to call EVP_PKEY_set1_RSA: " << GetOpenSSLError();
    return nullptr;
  }
  // Calculate the public key digest if needed.
  if (public_key_digest != nullptr) {
    *public_key_digest = base::SHA1HashString(std::string(
        parsed.pubKey.key, parsed.pubKey.key + parsed.pubKey.keyLength));
  }

  return key;
}

std::string ToPcrComposite(uint32_t pcr_index, const std::string& pcr_value) {
  // Unfortunately trousers doesn't provide useful helpers to do this so we have
  // to do it here.
  CHECK_EQ(pcr_value.length(), kExpectedPcrLength);
  struct __attribute__((packed)) {
    // Corresponding to TPM_PCR_SELECTION.sizeOfSelect.
    uint16_t select_size{htons(kSelectBitmapSize)};
    // Corresponding to TPM_PCR_SELECTION.pcrSelect.
    uint8_t select_bitmap[kSelectBitmapSize];
    // Corresponding to  TPM_PCR_COMPOSITE.valueSize.
    uint32_t value_size{htonl(kExpectedPcrLength)};
  } composite_header = {0};
  static_assert(sizeof(composite_header) ==
                    sizeof(uint16_t) + kSelectBitmapSize + sizeof(uint32_t),
                "Expect no padding between composite struct.");

  // Sets upt the bitmap.
  composite_header.select_bitmap[pcr_index / 8] = 1 << (pcr_index % 8);

  composite_header.select_size = (htons(2u));
  composite_header.select_bitmap[pcr_index / 8] = 1 << (pcr_index % 8);
  composite_header.value_size = htonl(pcr_value.length());

  const char* composite_header_buffer =
      reinterpret_cast<const char*>(&composite_header);
  return std::string(composite_header_buffer, sizeof(composite_header)) +
         pcr_value;
}

std::string Serialize(TPM_ASYM_CA_CONTENTS* contents) {
  std::unique_ptr<BYTE[]> blob(
      std::make_unique<BYTE[]>(sizeof(*contents) + contents->sessionKey.size));
  UINT64 offset = 0;
  Trspi_LoadBlob_ASYM_CA_CONTENTS(&offset, blob.get(), contents);
  return std::string(blob.get(), blob.get() + offset);
}

std::string Serialize(TPM_SYM_CA_ATTESTATION* contents) {
  std::unique_ptr<BYTE[]> blob(
      std::make_unique<BYTE[]>(sizeof(*contents) + contents->credSize));
  UINT64 offset = 0;
  Trspi_LoadBlob_SYM_CA_ATTESTATION(&offset, blob.get(), contents);
  return std::string(blob.get(), blob.get() + offset);
}

std::optional<std::string> ParseDigestFromTpmCertifyInfo(
    const std::string& serialized) {
  TPM_CERTIFY_INFO parsed{};
  uint64_t offset = 0;
  TSS_RESULT result = Trspi_UnloadBlob_CERTIFY_INFO(
      &offset, reinterpret_cast<BYTE*>(const_cast<char*>(serialized.data())),
      &parsed);
  if (result != TSS_SUCCESS) {
    TPM_LOG(ERROR, result) << "Failed to parse TPM_CERTIFY_INFO.";
    return {};
  }

  // Prevent memory leak.
  std::unique_ptr<BYTE, base::FreeDeleter> scoped_key(
      parsed.algorithmParms.parms);
  return std::string(
      parsed.pubkeyDigest.digest,
      parsed.pubkeyDigest.digest + sizeof(parsed.pubkeyDigest.digest));
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
