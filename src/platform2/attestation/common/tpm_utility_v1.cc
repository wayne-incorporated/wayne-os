// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/tpm_utility_v1.h"

#include <arpa/inet.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <trousers/scoped_tss_type.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <vector>

#define TPM_LOG(severity, result)                               \
  LOG(severity) << "TPM error 0x" << std::hex << result << " (" \
                << Trspi_Error_String(result) << "): "

using trousers::ScopedTssContext;
using trousers::ScopedTssKey;
using trousers::ScopedTssMemory;
using trousers::ScopedTssPcrs;
using trousers::ScopedTssPolicy;
namespace {

using ScopedByteArray = std::unique_ptr<BYTE, base::FreeDeleter>;
using ScopedTssEncryptedData = trousers::ScopedTssObject<TSS_HENCDATA>;
using ScopedTssHash = trousers::ScopedTssObject<TSS_HHASH>;

constexpr unsigned int kDefaultTpmRsaKeyBits = 2048;
constexpr unsigned int kDefaultTpmRsaKeyFlag = TSS_KEY_SIZE_2048;
constexpr unsigned int kWellKnownExponent = 65537;
constexpr unsigned char kSha256DigestInfo[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

BYTE* StringAsTSSBuffer(std::string* s) {
  return reinterpret_cast<BYTE*>(std::data(*s));
}

BYTE* StringAsTSSBuffer(const std::string* s) {
  return StringAsTSSBuffer(const_cast<std::string*>(s));
}

std::string TSSBufferAsString(const BYTE* buffer, size_t length) {
  return std::string(reinterpret_cast<const char*>(buffer), length);
}

// Checks if `delegate_blob`'s flag `TPM_DELEGATE_OwnerReadInternalPub` is set.
// In case of empty input or failed parsing, returns `false`; otherwise, set
// `can_read` and returns `true`.
bool CanDelegateReadInternalPub(const std::string& delegate_blob,
                                bool* can_read) {
  if (delegate_blob.empty()) {
    LOG(ERROR) << __func__ << ": Empty blob.";
    return false;
  }
  UINT64 offset = 0;
  // Make sure the parsing will be successful first.
  TSS_RESULT result = Trspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB(
      &offset,
      const_cast<BYTE*>(reinterpret_cast<const BYTE*>(delegate_blob.data())),
      nullptr);
  if (offset != delegate_blob.size()) {
    TPM_LOG(ERROR, result) << __func__ << ": Bad delegate blob.";
    return false;
  }
  offset = 0;

  TPM_DELEGATE_OWNER_BLOB ownerBlob = {};

  // TODO(b/169392230): Fix the potential memory leak while migrating to tpm
  // manager.
  result = Trspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB(
      &offset,
      const_cast<BYTE*>(reinterpret_cast<const BYTE*>(delegate_blob.data())),
      &ownerBlob);

  if (result != TSS_SUCCESS) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to unload delegate blob.";
    return false;
  }

  *can_read =
      ownerBlob.pub.permissions.per1 & TPM_DELEGATE_OwnerReadInternalPub;
  return true;
}

}  // namespace

namespace attestation {

TpmUtilityV1::TpmUtilityV1(tpm_manager::TpmManagerUtility* tpm_manager_utility)
    : TpmUtilityCommon(tpm_manager_utility) {}

TpmUtilityV1::~TpmUtilityV1() {}

bool TpmUtilityV1::Initialize() {
  if (!TpmUtilityCommon::Initialize()) {
    LOG(ERROR) << __func__ << ": Cannot initialize TpmUtilityCommon.";
    return false;
  }
  if (!InitializeContextHandle(__func__)) {
    LOG(WARNING) << __func__
                 << ": Failed to connect to the TPM during initialization.";
  }
  if (!IsTpmReady()) {
    LOG(WARNING) << __func__ << ": TPM is not owned; attestation services will "
                 << "not be available until ownership is taken.";
  }
  return true;
}

std::vector<KeyType> TpmUtilityV1::GetSupportedKeyTypes() {
  return {KEY_TYPE_RSA};
}

bool TpmUtilityV1::ActivateIdentity(const std::string& identity_key_blob,
                                    const std::string& asym_ca_contents,
                                    const std::string& sym_ca_attestation,
                                    std::string* credential) {
  CHECK(credential);
  if (!SetupSrk()) {
    LOG(ERROR) << "SRK is not ready.";
    return false;
  }

  // Connect to the TPM as the owner delegate.
  ScopedTssContext context_handle;
  TSS_HTPM tpm_handle;
  if (!ConnectContextAsDelegate(delegate_blob_, delegate_secret_,
                                &context_handle, &tpm_handle)) {
    LOG(ERROR) << __func__ << ": Could not connect to the TPM.";
    return false;
  }
  // Load the Storage Root Key.
  TSS_RESULT result;
  ScopedTssKey srk_handle(context_handle);
  if (!LoadSrk(context_handle, &srk_handle)) {
    LOG(ERROR) << __func__ << ": Failed to load SRK.";
    return false;
  }
  // Load the AIK (which is wrapped by the SRK).
  std::string mutable_identity_key_blob(identity_key_blob);
  BYTE* identity_key_blob_buffer =
      StringAsTSSBuffer(&mutable_identity_key_blob);
  ScopedTssKey identity_key(context_handle);
  result = Tspi_Context_LoadKeyByBlob(
      context_handle, srk_handle, identity_key_blob.size(),
      identity_key_blob_buffer, identity_key.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to load AIK.";
    return false;
  }
  std::string mutable_asym_ca_contents(asym_ca_contents);
  BYTE* asym_ca_contents_buffer = StringAsTSSBuffer(&mutable_asym_ca_contents);
  std::string mutable_sym_ca_attestation(sym_ca_attestation);
  BYTE* sym_ca_attestation_buffer =
      StringAsTSSBuffer(&mutable_sym_ca_attestation);
  UINT32 credential_length = 0;
  ScopedTssMemory credential_buffer(context_handle);
  result = Tspi_TPM_ActivateIdentity(
      tpm_handle, identity_key, asym_ca_contents.size(),
      asym_ca_contents_buffer, sym_ca_attestation.size(),
      sym_ca_attestation_buffer, &credential_length, credential_buffer.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to activate identity.";
    return false;
  }
  credential->assign(
      TSSBufferAsString(credential_buffer.value(), credential_length));
  return true;
}

bool TpmUtilityV1::ActivateIdentityForTpm2(
    KeyType key_type,
    const std::string& identity_key_blob,
    const std::string& encrypted_seed,
    const std::string& credential_mac,
    const std::string& wrapped_credential,
    std::string* credential) {
  LOG(ERROR) << __func__ << ": Not implemented.";
  return false;
}

bool TpmUtilityV1::CreateCertifiedKey(
    KeyType key_type,
    KeyUsage key_usage,
    KeyRestriction key_restriction,
    std::optional<CertificateProfile> profile_hint,
    const std::string& identity_key_blob,
    const std::string& external_data,
    std::string* key_blob,
    std::string* public_key,
    std::string* public_key_tpm_format,
    std::string* key_info,
    std::string* proof) {
  CHECK(key_blob && public_key && public_key_tpm_format && key_info && proof);
  if (!InitializeContextHandle(__func__)) {
    return false;
  }
  if (!SetupSrk()) {
    LOG(ERROR) << "SRK is not ready.";
    return false;
  }
  if (key_type != KEY_TYPE_RSA) {
    LOG(ERROR) << "Only RSA supported on TPM v1.2.";
    return false;
  }
  if (key_restriction == KeyRestriction::kRestricted) {
    LOG(ERROR) << "restricted key is not support for TPM1.2.";
    return false;
  }

  // Load the AIK (which is wrapped by the SRK).
  ScopedTssKey identity_key(context_handle_);
  if (!LoadKeyFromBlob(identity_key_blob, context_handle_, srk_handle_,
                       &identity_key)) {
    LOG(ERROR) << __func__ << "Failed to load AIK.";
    return false;
  }

  // Create a non-migratable RSA key.
  ScopedTssKey key(context_handle_);
  UINT32 tss_key_type =
      (key_usage == KEY_USAGE_SIGN) ? TSS_KEY_TYPE_SIGNING : TSS_KEY_TYPE_BIND;
  UINT32 init_flags = tss_key_type | TSS_KEY_NOT_MIGRATABLE | TSS_KEY_VOLATILE |
                      TSS_KEY_NO_AUTHORIZATION | TSS_KEY_SIZE_2048;
  TSS_RESULT result = Tspi_Context_CreateObject(
      context_handle_, TSS_OBJECT_TYPE_RSAKEY, init_flags, key.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to create object.";
    return false;
  }
  if (key_usage == KEY_USAGE_SIGN) {
    result = Tspi_SetAttribUint32(key, TSS_TSPATTRIB_KEY_INFO,
                                  TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                  TSS_SS_RSASSAPKCS1V15_DER);
  } else {
    result = Tspi_SetAttribUint32(key, TSS_TSPATTRIB_KEY_INFO,
                                  TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                  TSS_ES_RSAESOAEP_SHA1_MGF1);
  }
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to set scheme.";
    return false;
  }
  result = Tspi_Key_CreateKey(key, srk_handle_, 0);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to create key.";
    return false;
  }
  result = Tspi_Key_LoadKey(key, srk_handle_);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to load key.";
    return false;
  }

  // Certify the key.
  TSS_VALIDATION validation;
  memset(&validation, 0, sizeof(validation));
  validation.ulExternalDataLength = external_data.size();
  std::string mutable_external_data(external_data);
  validation.rgbExternalData = StringAsTSSBuffer(&mutable_external_data);
  result = Tspi_Key_CertifyKey(key, identity_key, &validation);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to certify key.";
    return false;
  }
  ScopedTssMemory scoped_certified_data(context_handle_, validation.rgbData);
  ScopedTssMemory scoped_proof(context_handle_, validation.rgbValidationData);

  // Get the certified public key.
  if (!GetDataAttribute(context_handle_, key, TSS_TSPATTRIB_KEY_BLOB,
                        TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
                        public_key_tpm_format)) {
    LOG(ERROR) << __func__ << ": Failed to read public key.";
    return false;
  }
  if (!GetRSAPublicKeyFromTpmPublicKey(*public_key_tpm_format, public_key)) {
    return false;
  }

  // Get the certified key blob so we can load it later.
  if (!GetDataAttribute(context_handle_, key, TSS_TSPATTRIB_KEY_BLOB,
                        TSS_TSPATTRIB_KEYBLOB_BLOB, key_blob)) {
    LOG(ERROR) << __func__ << ": Failed to read key blob.";
    return false;
  }

  // Get the data that was certified.
  key_info->assign(
      TSSBufferAsString(validation.rgbData, validation.ulDataLength));

  // Get the certification proof.
  proof->assign(TSSBufferAsString(validation.rgbValidationData,
                                  validation.ulValidationDataLength));
  return true;
}

bool TpmUtilityV1::GetEndorsementPublicKey(KeyType key_type,
                                           std::string* public_key_der) {
  if (key_type != KEY_TYPE_RSA) {
    return false;
  }
  ScopedTssContext context_handle;
  TSS_HTPM tpm_handle;
  bool is_ready = IsTpmReady();
  bool can_read_ek = false;
  if (!CanDelegateReadInternalPub(delegate_blob_, &can_read_ek)) {
    LOG(ERROR) << __func__ << ": Cannot check permission.";
  }
  LOG_IF(WARNING, !can_read_ek)
      << __func__ << ": owner delegate cannot read ek.";

  // Rationality check of auth values, if necessary.
  if (is_ready && !can_read_ek && owner_password_.empty()) {
    LOG(ERROR) << __func__ << ": No valid auth.";
    return false;
  }

  if (!is_ready) {
    if (!ConnectContextAsUser(&context_handle, &tpm_handle)) {
      LOG(ERROR) << __func__ << ": Could not connect to the TPM as user.";
      return false;
    }
  } else if (can_read_ek) {
    if (!ConnectContextAsDelegate(delegate_blob_, delegate_secret_,
                                  &context_handle, &tpm_handle)) {
      LOG(ERROR) << __func__ << ": Could not connect to the TPM as delegate.";
      return false;
    }
  } else if (!owner_password_.empty()) {
    if (!ConnectContextAsOwner(owner_password_, &context_handle, &tpm_handle)) {
      LOG(ERROR) << __func__ << ": Could not connect to the TPM as owner.";
      return false;
    }
  } else {
    NOTREACHED();
    return false;
  }

  // Get a handle to the EK public key.
  ScopedTssKey ek_public_key_object(context_handle);
  TSS_RESULT result = Tspi_TPM_GetPubEndorsementKey(
      tpm_handle, is_ready, nullptr, ek_public_key_object.ptr());
  if (TPM_ERROR(result)) {
    if (!is_ready && IsTpmReady()) {
      LOG(INFO) << " ownership taken during retrieval of EK. Retry.";
      return GetEndorsementPublicKey(key_type, public_key_der);
    }
    TPM_LOG(ERROR, result) << __func__ << ": Failed to get key.";
    return false;
  }
  // Get the public key in TPM_PUBKEY form.
  std::string ek_public_key_blob;
  if (!GetDataAttribute(
          context_handle, ek_public_key_object, TSS_TSPATTRIB_KEY_BLOB,
          TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &ek_public_key_blob)) {
    LOG(ERROR) << __func__ << ": Failed to read public key.";
    return false;
  }
  // Get the public key in DER encoded form.
  if (!GetRSAPublicKeyFromTpmPublicKey(ek_public_key_blob, public_key_der)) {
    return false;
  }
  return true;
}

bool TpmUtilityV1::GetEndorsementCertificate(KeyType key_type,
                                             std::string* certificate) {
  // Connect to the TPM as the owner.
  ScopedTssContext context_handle;
  TSS_HTPM tpm_handle;
  if (!ConnectContextAsOwner(owner_password_, &context_handle, &tpm_handle)) {
    LOG(ERROR) << __func__ << " Could not connect to the TPM.";
    return false;
  }

  // Use the owner secret to authorize reading the blob.
  ScopedTssPolicy policy_handle(context_handle);
  TSS_RESULT result;
  result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_POLICY,
                                     TSS_POLICY_USAGE, policy_handle.ptr());
  if (TPM_ERROR(result)) {
    LOG(ERROR) << __func__ << " Could not create policy.";
    return false;
  }
  result = Tspi_Policy_SetSecret(
      policy_handle, TSS_SECRET_MODE_PLAIN, owner_password_.size(),
      reinterpret_cast<BYTE*>(
          const_cast<std::string::value_type*>(owner_password_.data())));
  if (TPM_ERROR(result)) {
    LOG(ERROR) << __func__ << " Could not set owner secret.";
    return false;
  }

  // Read the EK cert from NVRAM.
  std::string nvram_value;
  if (!ReadNvram(context_handle, tpm_handle, policy_handle,
                 TSS_NV_DEFINED | TPM_NV_INDEX_EKCert, &nvram_value)) {
    LOG(ERROR) << __func__ << " Failed to read NVRAM.";
    return false;
  }

  // Sanity check the contents of the data and extract the X.509 certificate.
  // We are expecting data in the form of a TCG_PCCLIENT_STORED_CERT with an
  // embedded TCG_FULL_CERT. Details can be found in the TCG PC Specific
  // Implementation Specification v1.21 section 7.4.
  constexpr uint8_t kStoredCertHeader[] = {0x10, 0x01, 0x00};
  constexpr uint8_t kFullCertHeader[] = {0x10, 0x02};
  constexpr size_t kTotalHeaderBytes = 7;
  constexpr size_t kStoredCertHeaderOffset = 0;
  constexpr size_t kFullCertLengthOffset = 3;
  constexpr size_t kFullCertHeaderOffset = 5;
  if (nvram_value.size() < kTotalHeaderBytes) {
    LOG(ERROR) << "Malformed EK certificate: Bad header.";
    return false;
  }
  if (memcmp(kStoredCertHeader, &nvram_value[kStoredCertHeaderOffset],
             std::size(kStoredCertHeader)) != 0) {
    LOG(ERROR) << "Malformed EK certificate: Bad PCCLIENT_STORED_CERT.";
    return false;
  }
  if (memcmp(kFullCertHeader, &nvram_value[kFullCertHeaderOffset],
             std::size(kFullCertHeader)) != 0) {
    LOG(ERROR) << "Malformed EK certificate: Bad PCCLIENT_FULL_CERT.";
    return false;
  }
  // The size value is represented by two bytes in network order.
  size_t full_cert_size =
      (size_t(uint8_t(nvram_value[kFullCertLengthOffset])) << 8) |
      uint8_t(nvram_value[kFullCertLengthOffset + 1]);
  if (full_cert_size + kFullCertHeaderOffset > nvram_value.size()) {
    LOG(ERROR) << "Malformed EK certificate: Bad size.";
    return false;
  }
  // The X.509 certificate follows the header bytes.
  size_t full_cert_end =
      kTotalHeaderBytes + full_cert_size - std::size(kFullCertHeader);
  certificate->assign(nvram_value.begin() + kTotalHeaderBytes,
                      nvram_value.begin() + full_cert_end);
  return true;
}

bool TpmUtilityV1::Unbind(const std::string& key_blob,
                          const std::string& bound_data,
                          std::string* data) {
  CHECK(data);
  if (!InitializeContextHandle(__func__)) {
    return false;
  }
  if (!SetupSrk()) {
    LOG(ERROR) << "SRK is not ready.";
    return false;
  }
  ScopedTssKey key_handle(context_handle_);
  if (!LoadKeyFromBlob(key_blob, context_handle_, srk_handle_, &key_handle)) {
    return false;
  }
  TSS_RESULT result;
  ScopedTssEncryptedData data_handle(context_handle_);
  if (TPM_ERROR(result = Tspi_Context_CreateObject(
                    context_handle_, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND,
                    data_handle.ptr()))) {
    TPM_LOG(ERROR, result) << __func__ << ": Tspi_Context_CreateObject failed.";
    return false;
  }
  std::string mutable_bound_data(bound_data);
  if (TPM_ERROR(result = Tspi_SetAttribData(
                    data_handle, TSS_TSPATTRIB_ENCDATA_BLOB,
                    TSS_TSPATTRIB_ENCDATABLOB_BLOB, bound_data.size(),
                    StringAsTSSBuffer(&mutable_bound_data)))) {
    TPM_LOG(ERROR, result) << __func__ << ": Tspi_SetAttribData failed.";
    return false;
  }

  ScopedTssMemory decrypted_data(context_handle_);
  UINT32 length = 0;
  if (TPM_ERROR(result = Tspi_Data_Unbind(data_handle, key_handle, &length,
                                          decrypted_data.ptr()))) {
    TPM_LOG(ERROR, result) << __func__ << ": Tspi_Data_Unbind failed.";
    return false;
  }
  data->assign(TSSBufferAsString(decrypted_data.value(), length));
  return true;
}

bool TpmUtilityV1::Sign(const std::string& key_blob,
                        const std::string& data_to_sign,
                        std::string* signature) {
  CHECK(signature);
  if (!InitializeContextHandle(__func__)) {
    return false;
  }
  if (!SetupSrk()) {
    LOG(ERROR) << "SRK is not ready.";
    return false;
  }
  ScopedTssKey key_handle(context_handle_);
  if (!LoadKeyFromBlob(key_blob, context_handle_, srk_handle_, &key_handle)) {
    return false;
  }
  // Construct an ASN.1 DER DigestInfo.
  std::string digest_to_sign(std::begin(kSha256DigestInfo),
                             std::end(kSha256DigestInfo));
  digest_to_sign += crypto::SHA256HashString(data_to_sign);
  // Create a hash object to hold the digest.
  ScopedTssHash hash_handle(context_handle_);
  TSS_RESULT result = Tspi_Context_CreateObject(
      context_handle_, TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, hash_handle.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to create hash object.";
    return false;
  }
  result = Tspi_Hash_SetHashValue(hash_handle, digest_to_sign.size(),
                                  StringAsTSSBuffer(&digest_to_sign));
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to set hash data.";
    return false;
  }
  UINT32 length = 0;
  ScopedTssMemory buffer(context_handle_);
  result = Tspi_Hash_Sign(hash_handle, key_handle, &length, buffer.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to generate signature.";
    return false;
  }
  signature->assign(TSSBufferAsString(buffer.value(), length));
  return true;
}

bool TpmUtilityV1::ReadPCR(uint32_t pcr_index, std::string* pcr_value) {
  if (!InitializeContextHandle(__func__)) {
    return false;
  }
  UINT32 pcr_len = 0;
  ScopedTssMemory pcr_value_buffer(context_handle_);
  TSS_RESULT result = Tspi_TPM_PcrRead(tpm_handle_, pcr_index, &pcr_len,
                                       pcr_value_buffer.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Could not read PCR " << pcr_index << " value";
    return false;
  }
  pcr_value->assign(pcr_value_buffer.value(),
                    pcr_value_buffer.value() + pcr_len);
  return true;
}

bool TpmUtilityV1::GetNVDataSize(uint32_t nv_index, uint16_t* nv_size) const {
  LOG(ERROR) << __func__ << ": Not implemented.";
  return false;
}

bool TpmUtilityV1::CertifyNV(uint32_t nv_index,
                             int nv_size,
                             const std::string& key_blob,
                             std::string* quoted_data,
                             std::string* quote) {
  LOG(ERROR) << __func__ << ": Not implemented.";
  return false;
}

bool TpmUtilityV1::ConnectContextAsUser(ScopedTssContext* context,
                                        TSS_HTPM* tpm) {
  *tpm = 0;
  TSS_RESULT result;
  if (TPM_ERROR(result = Tspi_Context_Create(context->ptr()))) {
    TPM_LOG(ERROR, result) << __func__ << ": Error calling Tspi_Context_Create";
    return false;
  }
  if (TPM_ERROR(result = Tspi_Context_Connect(*context, nullptr))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_Context_Connect";
    return false;
  }
  if (TPM_ERROR(result = Tspi_Context_GetTpmObject(*context, tpm))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_Context_GetTpmObject";
    return false;
  }
  return true;
}
bool TpmUtilityV1::ConnectContextAsOwner(const std::string& owner_password,
                                         trousers::ScopedTssContext* context,
                                         TSS_HTPM* tpm) {
  *tpm = 0;
  if (owner_password.empty()) {
    LOG(ERROR) << __func__ << ": requires an owner password";
    return false;
  }

  if (!ConnectContextAsUser(context, tpm)) {
    LOG(ERROR) << __func__ << ": Could not open the TPM";
    return false;
  }

  if (!SetTpmOwnerAuth(owner_password, context->context(), *tpm)) {
    LOG(ERROR) << __func__ << ": failed to authorize as the owner";
    Tspi_Context_Close(*context);
    context->reset();
    *tpm = 0;
    return false;
  }
  return true;
}

bool TpmUtilityV1::ConnectContextAsDelegate(const std::string& delegate_blob,
                                            const std::string& delegate_secret,
                                            ScopedTssContext* context,
                                            TSS_HTPM* tpm) {
  if (delegate_blob.empty() || delegate_secret.empty()) {
    LOG(ERROR) << __func__
               << ": requires a delegate blob and a delegate secret.";
    return false;
  }
  *tpm = 0;
  if (!ConnectContextAsUser(context, tpm)) {
    return false;
  }
  TSS_RESULT result;
  TSS_HPOLICY tpm_usage_policy;
  if (TPM_ERROR(result = Tspi_GetPolicyObject(*tpm, TSS_POLICY_USAGE,
                                              &tpm_usage_policy))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_GetPolicyObject";
    return false;
  }
  std::string mutable_delegate_secret(delegate_secret);
  BYTE* secret_buffer = StringAsTSSBuffer(&mutable_delegate_secret);
  if (TPM_ERROR(result = Tspi_Policy_SetSecret(
                    tpm_usage_policy, TSS_SECRET_MODE_PLAIN,
                    delegate_secret.size(), secret_buffer))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_Policy_SetSecret";
    return false;
  }
  std::string mutable_delegate_blob(delegate_blob);
  BYTE* blob_buffer = StringAsTSSBuffer(&mutable_delegate_blob);
  if (TPM_ERROR(result = Tspi_SetAttribData(
                    tpm_usage_policy, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                    TSS_TSPATTRIB_POLDEL_OWNERBLOB, delegate_blob.size(),
                    blob_buffer))) {
    TPM_LOG(ERROR, result) << __func__ << ": Error calling Tspi_SetAttribData";
    return false;
  }
  return true;
}

bool TpmUtilityV1::SetTpmOwnerAuth(const std::string& owner_password,
                                   TSS_HCONTEXT context_handle,
                                   TSS_HTPM tpm_handle) {
  TSS_RESULT result;
  TSS_HPOLICY tpm_usage_policy;
  if (TPM_ERROR(result = Tspi_GetPolicyObject(tpm_handle, TSS_POLICY_USAGE,
                                              &tpm_usage_policy))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetPolicyObject";
    return false;
  }
  BYTE* owner_password_buffer = StringAsTSSBuffer(&owner_password);
  if (TPM_ERROR(result = Tspi_Policy_SetSecret(
                    tpm_usage_policy, TSS_SECRET_MODE_PLAIN,
                    owner_password.size(), owner_password_buffer))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    return false;
  }

  return true;
}

bool TpmUtilityV1::ReadNvram(TSS_HCONTEXT context_handle,
                             TSS_HTPM tpm_handle,
                             TSS_HPOLICY policy_handle,
                             uint32_t index,
                             std::string* blob) {
  UINT32 size = GetNvramSize(context_handle, tpm_handle, index);
  if (size == 0) {
    if (!IsNvramDefined(context_handle, tpm_handle, index)) {
      LOG(ERROR) << "Cannot read from non-existent NVRAM space.";
    } else {
      LOG(ERROR) << "Cannot get nvram size.";
    }
    return false;
  }
  blob->resize(size);

  // Create an NVRAM store object handle.
  TSS_RESULT result;
  trousers::ScopedTssNvStore nv_handle(context_handle);
  result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_NV, 0,
                                     nv_handle.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Could not acquire an NVRAM object handle";
    return false;
  }
  result = Tspi_SetAttribUint32(nv_handle, TSS_TSPATTRIB_NV_INDEX, 0, index);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Could not set index on NVRAM object: " << index;
    return false;
  }

  if (policy_handle) {
    result = Tspi_Policy_AssignToObject(policy_handle, nv_handle);
    if (TPM_ERROR(result)) {
      TPM_LOG(ERROR, result) << "Could not set NVRAM object policy.";
      return false;
    }
  }

  // Read from NVRAM in conservatively small chunks. This is a limitation of
  // the TPM that is left for the application layer to deal with. The maximum
  // size that is supported here can vary between vendors / models, so we'll
  // be conservative. FWIW, the Infineon chips seem to handle up to 1024.
  const UINT32 kMaxDataSize = 128;
  UINT32 offset = 0;
  while (offset < size) {
    UINT32 chunk_size = size - offset;
    if (chunk_size > kMaxDataSize)
      chunk_size = kMaxDataSize;
    trousers::ScopedTssMemory space_data(context_handle);
    if ((result = Tspi_NV_ReadValue(nv_handle, offset, &chunk_size,
                                    space_data.ptr()))) {
      TPM_LOG(ERROR, result) << "Could not read from NVRAM space: " << index;
      return false;
    }
    if (!space_data.value()) {
      LOG(ERROR) << "No data read from NVRAM space: " << index;
      return false;
    }
    CHECK(offset + chunk_size <= blob->size());
    // not for TSS APIs but BYTE* is also suitable here.
    BYTE* buffer = StringAsTSSBuffer(blob) + offset;
    memcpy(buffer, space_data.value(), chunk_size);
    offset += chunk_size;
  }
  return true;
}

bool TpmUtilityV1::IsNvramDefined(TSS_HCONTEXT context_handle,
                                  TSS_HTPM tpm_handle,
                                  uint32_t index) {
  TSS_RESULT result;
  UINT32 nv_list_data_length = 0;
  trousers::ScopedTssMemory nv_list_data(context_handle);
  if (TPM_ERROR(result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_NV_LIST,
                                                0, NULL, &nv_list_data_length,
                                                nv_list_data.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetCapability";
    return false;
  }

  // Walk the list and check if the index exists.
  UINT32* nv_list = reinterpret_cast<UINT32*>(nv_list_data.value());
  UINT32 nv_list_length = nv_list_data_length / sizeof(UINT32);
  index = htonl(index);  // TPM data is network byte order.
  for (UINT32 i = 0; i < nv_list_length; ++i) {
    // TODO(wad) add a NvramList method.
    if (index == nv_list[i])
      return true;
  }
  return false;
}

unsigned int TpmUtilityV1::GetNvramSize(TSS_HCONTEXT context_handle,
                                        TSS_HTPM tpm_handle,
                                        uint32_t index) {
  TSS_RESULT result;

  UINT32 nv_index_data_length = 0;
  trousers::ScopedTssMemory nv_index_data(context_handle);
  if (TPM_ERROR(result = Tspi_TPM_GetCapability(
                    tpm_handle, TSS_TPMCAP_NV_INDEX, sizeof(index),
                    reinterpret_cast<BYTE*>(&index), &nv_index_data_length,
                    nv_index_data.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetCapability";
    return 0u;
  }
  if (nv_index_data_length == 0) {
    return 0u;
  }
  // TPM_NV_DATA_PUBLIC->dataSize is the last element in the struct.
  // Since packing the struct still doesn't eliminate inconsistencies between
  // the API and the hardware, this is the safest way to extract the data.
  uint32_t* nv_data_public = reinterpret_cast<uint32_t*>(
      nv_index_data.value() + nv_index_data_length - sizeof(UINT32));
  return htonl(*nv_data_public);
}

bool TpmUtilityV1::SetupSrk() {
  if (!IsTpmReady()) {
    return false;
  }
  if (srk_handle_) {
    return true;
  }
  if (!InitializeContextHandle(__func__)) {
    return false;
  }
  srk_handle_.reset(context_handle_, 0);
  if (!LoadSrk(context_handle_, &srk_handle_)) {
    LOG(ERROR) << __func__ << ": Failed to load SRK.";
    return false;
  }
  // In order to wrap a key with the SRK we need access to the SRK public key
  // and we need to get it manually. Once it's in the key object, we don't need
  // to do this again.
  UINT32 length = 0;
  ScopedTssMemory buffer(context_handle_);
  TSS_RESULT result;
  result = Tspi_Key_GetPubKey(srk_handle_, &length, buffer.ptr());
  if (result != TSS_SUCCESS) {
    TPM_LOG(INFO, result) << __func__ << ": Failed to read SRK public key.";
    return false;
  }
  return true;
}

bool TpmUtilityV1::LoadSrk(TSS_HCONTEXT context_handle,
                           ScopedTssKey* srk_handle) {
  TSS_RESULT result;
  TSS_UUID uuid = TSS_UUID_SRK;
  if (TPM_ERROR(result = Tspi_Context_LoadKeyByUUID(context_handle,
                                                    TSS_PS_TYPE_SYSTEM, uuid,
                                                    srk_handle->ptr()))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_Context_LoadKeyByUUID";
    return false;
  }
  // Check if the SRK wants a password.
  UINT32 auth_usage;
  if (TPM_ERROR(result = Tspi_GetAttribUint32(
                    *srk_handle, TSS_TSPATTRIB_KEY_INFO,
                    TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &auth_usage))) {
    TPM_LOG(ERROR, result) << __func__
                           << ": Error calling Tspi_GetAttribUint32";
    return false;
  }
  if (auth_usage) {
    // Give it an empty password if needed.
    TSS_HPOLICY usage_policy;
    if (TPM_ERROR(result = Tspi_GetPolicyObject(*srk_handle, TSS_POLICY_USAGE,
                                                &usage_policy))) {
      TPM_LOG(ERROR, result)
          << __func__ << ": Error calling Tspi_GetPolicyObject";
      return false;
    }

    BYTE empty_password[] = {};
    if (TPM_ERROR(result =
                      Tspi_Policy_SetSecret(usage_policy, TSS_SECRET_MODE_PLAIN,
                                            0, empty_password))) {
      TPM_LOG(ERROR, result)
          << __func__ << ": Error calling Tspi_Policy_SetSecret";
      return false;
    }
  }
  return true;
}

bool TpmUtilityV1::LoadKeyFromBlob(const std::string& key_blob,
                                   TSS_HCONTEXT context_handle,
                                   TSS_HKEY parent_key_handle,
                                   ScopedTssKey* key_handle) {
  std::string mutable_key_blob(key_blob);
  BYTE* key_blob_buffer = StringAsTSSBuffer(&mutable_key_blob);
  TSS_RESULT result = Tspi_Context_LoadKeyByBlob(
      context_handle, parent_key_handle, key_blob.size(), key_blob_buffer,
      key_handle->ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << ": Failed to load key by blob.";
    return false;
  }
  return true;
}

bool TpmUtilityV1::GetDataAttribute(TSS_HCONTEXT context,
                                    TSS_HOBJECT object,
                                    TSS_FLAG flag,
                                    TSS_FLAG sub_flag,
                                    std::string* data) {
  UINT32 length = 0;
  ScopedTssMemory buffer(context);
  TSS_RESULT result =
      Tspi_GetAttribData(object, flag, sub_flag, &length, buffer.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << "Failed to read object attribute.";
    return false;
  }
  data->assign(TSSBufferAsString(buffer.value(), length));
  return true;
}

bool TpmUtilityV1::DecryptIdentityRequest(RSA* pca_key,
                                          const std::string& request,
                                          std::string* identity_binding) {
  // Parse the serialized TPM_IDENTITY_REQ structure.
  UINT64 offset = 0;
  BYTE* buffer = reinterpret_cast<BYTE*>(
      const_cast<typename std::string::value_type*>(request.data()));
  TPM_IDENTITY_REQ request_parsed;
  TSS_RESULT result =
      Trspi_UnloadBlob_IDENTITY_REQ(&offset, buffer, &request_parsed);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse identity request.";
    return false;
  }
  ScopedByteArray scoped_asym_blob(request_parsed.asymBlob);
  ScopedByteArray scoped_sym_blob(request_parsed.symBlob);

  // Decrypt the symmetric key.
  unsigned char key_buffer[kDefaultTpmRsaKeyBits / 8];
  int key_length =
      RSA_private_decrypt(request_parsed.asymSize, request_parsed.asymBlob,
                          key_buffer, pca_key, RSA_PKCS1_PADDING);
  if (key_length == -1) {
    LOG(ERROR) << "Failed to decrypt identity request key.";
    return false;
  }
  TPM_SYMMETRIC_KEY symmetric_key;
  offset = 0;
  result = Trspi_UnloadBlob_SYMMETRIC_KEY(&offset, key_buffer, &symmetric_key);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse symmetric key.";
    return false;
  }
  ScopedByteArray scoped_sym_key(symmetric_key.data);

  // Decrypt the request with the symmetric key.
  brillo::SecureBlob proof_serial;
  proof_serial.resize(request_parsed.symSize);
  UINT32 proof_serial_length = proof_serial.size();
  result = Trspi_SymDecrypt(symmetric_key.algId, TPM_ES_SYM_CBC_PKCS5PAD,
                            symmetric_key.data, NULL, request_parsed.symBlob,
                            request_parsed.symSize, proof_serial.data(),
                            &proof_serial_length);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to decrypt identity request.";
    return false;
  }

  // Parse the serialized TPM_IDENTITY_PROOF structure.
  TPM_IDENTITY_PROOF proof;
  offset = 0;
  result =
      Trspi_UnloadBlob_IDENTITY_PROOF(&offset, proof_serial.data(), &proof);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse identity proof.";
    return false;
  }
  ScopedByteArray scoped_label(proof.labelArea);
  ScopedByteArray scoped_binding(proof.identityBinding);
  ScopedByteArray scoped_endorsement(proof.endorsementCredential);
  ScopedByteArray scoped_platform(proof.platformCredential);
  ScopedByteArray scoped_conformance(proof.conformanceCredential);
  ScopedByteArray scoped_key(proof.identityKey.pubKey.key);
  ScopedByteArray scoped_parms(proof.identityKey.algorithmParms.parms);

  identity_binding->assign(&proof.identityBinding[0],
                           &proof.identityBinding[proof.identityBindingSize]);
  brillo::SecureClearBytes(proof.identityBinding, proof.identityBindingSize);
  return true;
}

bool TpmUtilityV1::GetRSAPublicKeyFromTpmPublicKey(
    const std::string& tpm_public_key_object, std::string* public_key_der) {
  // Parse the serialized TPM_PUBKEY.
  UINT64 offset = 0;
  std::string mutable_public_key(tpm_public_key_object);
  BYTE* buffer = StringAsTSSBuffer(&mutable_public_key);
  TPM_PUBKEY parsed;
  TSS_RESULT result = Trspi_UnloadBlob_PUBKEY_s(
      &offset, buffer, mutable_public_key.length(), &parsed);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse TPM_PUBKEY.";
    return false;
  }
  ScopedByteArray scoped_key(parsed.pubKey.key);
  ScopedByteArray scoped_parms(parsed.algorithmParms.parms);
  if (offset != mutable_public_key.length()) {
    LOG(ERROR) << "Found garbage data after the TPM_PUBKEY.";
    return false;
  }
  TPM_RSA_KEY_PARMS parms;
  UINT64 parms_offset = 0;
  result = Trspi_UnloadBlob_RSA_KEY_PARMS_s(
      &parms_offset, parsed.algorithmParms.parms,
      parsed.algorithmParms.parmSize, &parms);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "Failed to parse RSA_KEY_PARMS.";
    return false;
  }
  if (parms_offset != parsed.algorithmParms.parmSize) {
    LOG(ERROR) << "Find garbage data after the TPM_PUBKEY.";
    return false;
  }
  ScopedByteArray scoped_exponent(parms.exponent);
  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  if (!rsa || !e || !n) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM.";
    return false;
  }
  // Get the public exponent.
  if (parms.exponentSize == 0) {
    if (!BN_set_word(e.get(), kWellKnownExponent)) {
      LOG(ERROR) << "Failed to set exponent to WellKnownExponent.";
      return false;
    }
  } else {
    if (!BN_bin2bn(parms.exponent, parms.exponentSize, e.get())) {
      LOG(ERROR) << "Failed to convert exponent to BIGNUM.";
      return false;
    }
  }
  // Get the modulus.
  if (!BN_bin2bn(parsed.pubKey.key, parsed.pubKey.keyLength, n.get())) {
    LOG(ERROR) << "Failed to convert public key to BIGNUM.";
    return false;
  }
  if (!RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr)) {
    LOG(ERROR) << ": Failed to set exponent or modulus.";
    return false;
  }

  // DER encode.
  int der_length = i2d_RSAPublicKey(rsa.get(), nullptr);
  if (der_length < 0) {
    LOG(ERROR) << "Failed to DER-encode public key.";
    return false;
  }
  public_key_der->resize(der_length);
  unsigned char* der_buffer =
      reinterpret_cast<unsigned char*>(std::data(*public_key_der));
  der_length = i2d_RSAPublicKey(rsa.get(), &der_buffer);
  if (der_length < 0) {
    LOG(ERROR) << "Failed to DER-encode public key.";
    return false;
  }
  public_key_der->resize(der_length);
  return true;
}

bool TpmUtilityV1::GetEndorsementPublicKeyModulus(KeyType key_type,
                                                  std::string* ekm) {
  if (key_type != KEY_TYPE_RSA) {
    LOG(ERROR) << __func__ << ": Only RSA supported on TPM1.2.";
    return false;
  }
  std::string ek_public_key;
  if (!GetEndorsementPublicKey(key_type, &ek_public_key)) {
    LOG(ERROR) << __func__ << ": Failed to get EK public key.";
    return false;
  }

  // Extracts the modulus from the public key.
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(ek_public_key.data());
  crypto::ScopedRSA public_key(
      d2i_RSAPublicKey(nullptr, &asn1_ptr, ek_public_key.size()));
  if (!public_key.get()) {
    LOG(ERROR) << __func__ << ": Failed to decode public endorsement key.";
    return false;
  }
  int modulus_bytes_length = RSA_size(public_key.get());
  if (modulus_bytes_length <= 0) {
    LOG(ERROR) << __func__
               << ": Failed to get public endorsement key modulus length.";
    return false;
  }
  std::vector<uint8_t> modulus_bytes(modulus_bytes_length);
  const BIGNUM* n;
  RSA_get0_key(public_key.get(), &n, nullptr, nullptr);
  int output_length = BN_bn2bin(n, modulus_bytes.data());
  if (output_length != modulus_bytes_length) {
    LOG(ERROR) << __func__ << ": Bad length returned by BN_bn2bin: got "
               << output_length << " while it should be "
               << modulus_bytes_length;
    return false;
  }
  ekm->assign(modulus_bytes.begin(), modulus_bytes.end());
  return true;
}

bool TpmUtilityV1::GetEndorsementPublicKeyBytes(KeyType key_type,
                                                std::string* ek_bytes) {
  if (key_type != KEY_TYPE_RSA) {
    LOG(ERROR) << __func__ << ": Only RSA supported on TPM1.2.";
    return false;
  }
  return GetEndorsementPublicKeyModulus(key_type, ek_bytes);
}

bool TpmUtilityV1::CreateIdentity(KeyType key_type,
                                  AttestationDatabase::Identity* identity) {
  if (KEY_TYPE_RSA != key_type) {
    LOG(ERROR) << __func__ << ": Identity key only supports RSA key type.";
    return false;
  }
  // fill the fields in identity
  auto binding_pb = identity->mutable_identity_binding();
  auto key_pb = identity->mutable_identity_key();
  if (!MakeIdentity(key_pb->mutable_identity_public_key_der(),
                    binding_pb->mutable_identity_public_key_tpm_format(),
                    key_pb->mutable_identity_key_blob(),
                    binding_pb->mutable_identity_binding(),
                    binding_pb->mutable_identity_label(),
                    binding_pb->mutable_pca_public_key())) {
    LOG(ERROR) << __func__ << ": Failed to make identity.";
    return false;
  }
  key_pb->set_identity_key_type(key_type);
  binding_pb->set_identity_public_key_der(key_pb->identity_public_key_der());
  return true;
}

bool TpmUtilityV1::MakeIdentity(std::string* identity_public_key_der,
                                std::string* identity_public_key,
                                std::string* identity_key_blob,
                                std::string* identity_binding,
                                std::string* identity_label,
                                std::string* pca_public_key) {
  CHECK(identity_public_key_der && identity_public_key && identity_key_blob &&
        identity_binding && identity_label && pca_public_key);
  // Connect to the TPM as the owner.
  ScopedTssContext context_handle;
  TSS_HTPM tpm_handle;
  if (!ConnectContextAsOwner(owner_password_, &context_handle, &tpm_handle)) {
    LOG(ERROR) << __func__ << " Could not connect to the TPM.";
    return false;
  }

  // Load the Storage Root Key.
  TSS_RESULT result;
  ScopedTssKey srk_handle(context_handle);
  if (!LoadSrk(context_handle, &srk_handle)) {
    LOG(ERROR) << "MakeIdentity: Cannot load SRK.";
    return false;
  }

  crypto::ScopedRSA fake_pca_key(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!fake_pca_key || !e) {
    LOG(ERROR) << "MakeIdentity: Failed to allocate RSA or BIGNUM.";
    return false;
  }

  if (!BN_set_word(e.get(), kWellKnownExponent) ||
      !RSA_generate_key_ex(fake_pca_key.get(), kDefaultTpmRsaKeyBits, e.get(),
                           nullptr)) {
    LOG(ERROR) << "MakeIdentity: Failed to generate local key pair.";
    return false;
  }
  unsigned char modulus_buffer[kDefaultTpmRsaKeyBits / 8];
  const BIGNUM* n;
  RSA_get0_key(fake_pca_key.get(), &n, NULL, NULL);
  if (BN_bn2bin(n, modulus_buffer) != RSA_size(fake_pca_key.get())) {
    LOG(ERROR) << "MakeIdentity: Failed to convert modulus from BIGNUM.";
    return false;
  }

  // Create a TSS object for the fake PCA public key.
  ScopedTssKey pca_public_key_object(context_handle);
  constexpr UINT32 kPcaKeyFlags =
      kDefaultTpmRsaKeyFlag | TSS_KEY_TYPE_LEGACY | TSS_KEY_MIGRATABLE;
  result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_RSAKEY,
                                     kPcaKeyFlags, pca_public_key_object.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "MakeIdentity: Cannot create PCA public key.";
    return false;
  }
  result = Tspi_SetAttribData(pca_public_key_object, TSS_TSPATTRIB_RSAKEY_INFO,
                              TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
                              std::size(modulus_buffer), modulus_buffer);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result)
        << "MakeIdentity: Cannot set modulus to PCA public key.";
    return false;
  }
  result = Tspi_SetAttribUint32(pca_public_key_object, TSS_TSPATTRIB_KEY_INFO,
                                TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                TSS_ES_RSAESPKCSV15);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "MakeIdentity: Cannot set encoding scheme "
                              "attribute to PCA public key.";
    return false;
  }

  // Get the fake PCA public key in serialized TPM_PUBKEY form.
  if (!GetDataAttribute(context_handle, pca_public_key_object,
                        TSS_TSPATTRIB_KEY_BLOB,
                        TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pca_public_key)) {
    LOG(ERROR) << __func__ << ": Failed to read public key.";
    return false;
  }

  // Construct an arbitrary unicode label.
  const char* label_text = "ChromeOS_AIK_1BJNAMQDR4RH44F4ET2KPAOMJMO043K1";
  BYTE* label_ascii =
      const_cast<BYTE*>(reinterpret_cast<const BYTE*>(label_text));
  unsigned int label_size = strlen(label_text);
  ScopedByteArray label(Trspi_Native_To_UNICODE(label_ascii, &label_size));
  if (!label.get()) {
    LOG(ERROR) << "MakeIdentity: Failed to create AIK label.";
    return false;
  }
  identity_label->assign(&label.get()[0], &label.get()[label_size]);

  // Initialize a key object to hold the new identity key.
  ScopedTssKey identity_key(context_handle);
  constexpr UINT32 kIdentityKeyFlags =
      kDefaultTpmRsaKeyFlag | TSS_KEY_TYPE_IDENTITY | TSS_KEY_VOLATILE |
      TSS_KEY_NOT_MIGRATABLE;
  result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_RSAKEY,
                                     kIdentityKeyFlags, identity_key.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "MakeIdentity: Failed to create key object.";
    return false;
  }

  // Create the identity and receive the request intended for the PCA.
  UINT32 request_length = 0;
  ScopedTssMemory request(context_handle);
  result = Tspi_TPM_CollateIdentityRequest(
      tpm_handle, srk_handle, pca_public_key_object, label_size, label.get(),
      identity_key, TSS_ALG_3DES, &request_length, request.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "MakeIdentity: Failed to make identity.";
    return false;
  }

  // Decrypt and parse the identity request.
  std::string request_blob(request.value(), request.value() + request_length);
  if (!DecryptIdentityRequest(fake_pca_key.get(), request_blob,
                              identity_binding)) {
    LOG(ERROR) << "MakeIdentity: Failed to decrypt the identity request.";
    return false;
  }
  brillo::SecureClearBytes(request.value(), request_length);

  // Get the AIK public key.
  if (!GetDataAttribute(context_handle, identity_key, TSS_TSPATTRIB_KEY_BLOB,
                        TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
                        identity_public_key)) {
    LOG(ERROR) << __func__ << ": Failed to read public key.";
    return false;
  }
  if (!GetRSAPublicKeyFromTpmPublicKey(*identity_public_key,
                                       identity_public_key_der)) {
    return false;
  }

  // Get the AIK blob so we can load it later.
  if (!GetDataAttribute(context_handle, identity_key, TSS_TSPATTRIB_KEY_BLOB,
                        TSS_TSPATTRIB_KEYBLOB_BLOB, identity_key_blob)) {
    LOG(ERROR) << __func__ << ": Failed to read key blob.";
    return false;
  }
  return true;
}

bool TpmUtilityV1::InitializeContextHandle(const std::string& consumer_name) {
  if (!static_cast<TSS_HCONTEXT>(context_handle_) || !tpm_handle_) {
    context_handle_.reset();
    if (!ConnectContextAsUser(&context_handle_, &tpm_handle_)) {
      LOG(ERROR) << __func__ << ": Failed to connect to the TPM.";
      return false;
    }
  }
  return true;
}

}  // namespace attestation
