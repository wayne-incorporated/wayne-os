// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/local_data_migration.h"

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/secure_util.h>
#include <libhwsec/frontend/local_data_migration/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <limits>
#include <memory>

#include "tpm_manager/proto_bindings/tpm_manager.pb.h"

using ::hwsec::TPMError;

namespace {

constexpr size_t kAesBlockSize = 16;

// The following few functions are simplied to minimum from
// "attestation/common/crypto_utility_impl.cc" so we can decrypt the encrypted
// database. Modifications are also made in order to replace |std::string| in
// the function signature and get rid of reinterpret_cast.
//
// TODO(cylai): replace this with calls to commmon library once we have a
// library shared across all hwsec daemons.
std::string GetOpenSSLError() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* data = nullptr;
  int data_len = BIO_get_mem_data(bio, &data);
  std::string error_string(data, data_len);
  BIO_free(bio);
  return error_string;
}

unsigned char* SecureBlobAsSSLBuffer(const brillo::SecureBlob& blob) {
  return static_cast<unsigned char*>(
      const_cast<brillo::SecureBlob::value_type*>(blob.data()));
}

brillo::SecureBlob HmacSha512(const brillo::SecureBlob& key,
                              const brillo::SecureBlob& data) {
  brillo::SecureBlob mac;
  mac.resize(SHA512_DIGEST_LENGTH);
  HMAC(EVP_sha512(), SecureBlobAsSSLBuffer(key), key.size(),
       SecureBlobAsSSLBuffer(data), data.size(), mac.data(), nullptr);
  return mac;
}

// Decrypts |encrypted_data| using |key|, |iv|, and the given |cipher|.
// Returns true on success.
bool AesDecrypt(const EVP_CIPHER* cipher,
                const brillo::SecureBlob& encrypted_data,
                const brillo::SecureBlob& key,
                const brillo::SecureBlob& iv,
                brillo::SecureBlob* data) {
  if (key.size() != static_cast<size_t>(EVP_CIPHER_key_length(cipher)) ||
      iv.size() != kAesBlockSize) {
    return false;
  }
  if (encrypted_data.size() >
      static_cast<size_t>(std::numeric_limits<int>::max())) {
    // EVP_DecryptUpdate takes a signed int.
    return false;
  }
  unsigned char* input_buffer = SecureBlobAsSSLBuffer(encrypted_data);
  unsigned char* key_buffer = SecureBlobAsSSLBuffer(key);
  unsigned char* iv_buffer = SecureBlobAsSSLBuffer(iv);
  // Allocate enough space for the output.
  data->resize(encrypted_data.size());
  unsigned char* output_buffer = SecureBlobAsSSLBuffer(*data);
  int output_size = 0;
  crypto::ScopedEVP_CIPHER_CTX decryption_context(EVP_CIPHER_CTX_new());
  if (!decryption_context) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_DecryptInit_ex(decryption_context.get(), cipher, nullptr, key_buffer,
                          iv_buffer)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_DecryptUpdate(decryption_context.get(), output_buffer, &output_size,
                         input_buffer, encrypted_data.size())) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  size_t total_size = output_size;
  output_buffer += output_size;
  output_size = 0;
  if (!EVP_DecryptFinal_ex(decryption_context.get(), output_buffer,
                           &output_size)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  total_size += output_size;
  data->resize(total_size);
  return true;
}

// Decrypts |input| using |key|. On success populates
// |decrypted| and returns |true|.
bool Decrypt(const attestation::EncryptedData& input,
             const brillo::SecureBlob& key,
             brillo::SecureBlob* decrypted) {
  const brillo::SecureBlob expected_mac =
      HmacSha512(key, brillo::SecureBlob(input.iv() + input.encrypted_data()));

  if (expected_mac.size() != input.mac().length()) {
    LOG(ERROR) << __func__ << ": MAC length mismatch." << ' '
               << expected_mac.size() << ' ' << input.mac().length();
    return false;
  }
  if (!crypto::SecureMemEqual(expected_mac.data(), input.mac().data(),
                              input.mac().length())) {
    LOG(ERROR) << __func__ << ": MAC mismatch.";
    return false;
  }
  if (!AesDecrypt(EVP_aes_256_cbc(), brillo::SecureBlob(input.encrypted_data()),
                  key, brillo::SecureBlob(input.iv()), decrypted)) {
    return false;
  }
  return true;
}

// Parses and decrypts |encrypted_database| into a |LegacyAttestationDatabase|.
// |hwsec| is used to unseal the wrapped key in the |encrypted_database|.
bool DecryptAttestationDatabase(
    const brillo::SecureBlob& encrypted_database,
    const hwsec::LocalDataMigrationFrontend* hwsec,
    tpm_manager::LegacyAttestationDatabase* database) {
  attestation::EncryptedData encrypted_data;
  if (!encrypted_data.ParseFromString(encrypted_database.to_string())) {
    LOG(ERROR) << __func__
               << ": Failed to parse data into |EncryptedData| message.";
    return false;
  }
  ASSIGN_OR_RETURN(
      brillo::SecureBlob key,
      hwsec->Unseal(brillo::BlobFromString(encrypted_data.wrapped_key())),
      _.WithStatus<TPMError>("Failed to unseal the encrypting key")
          .LogError()
          .As(false));

  brillo::SecureBlob decrypted_database_blob;
  if (!Decrypt(encrypted_data, key, &decrypted_database_blob)) {
    LOG(ERROR) << __func__ << ": Failed to decrypt the database blob.";
    return false;
  }
  if (!database->ParseFromArray(decrypted_database_blob.data(),
                                decrypted_database_blob.size())) {
    LOG(ERROR) << __func__ << ": Failed to parse attestation database.";
    return false;
  }
  return true;
}

tpm_manager::AuthDelegate LegacyDelegationToAuthDelegate(
    const tpm_manager::LegacyDelegation& old_delegate) {
  tpm_manager::AuthDelegate new_delegate;
  new_delegate.mutable_blob()->assign(old_delegate.blob());
  new_delegate.mutable_secret()->assign(old_delegate.secret());
  new_delegate.set_has_reset_lock_permissions(
      old_delegate.has_reset_lock_permissions());
  return new_delegate;
}

}  // namespace

namespace tpm_manager {

bool MigrateAuthDelegate(const brillo::SecureBlob& sealed_database,
                         const hwsec::LocalDataMigrationFrontend* hwsec,
                         tpm_manager::AuthDelegate* delegate) {
  CHECK(delegate != nullptr);
  CHECK(hwsec != nullptr);

  LegacyAttestationDatabase old_database;
  if (!DecryptAttestationDatabase(sealed_database, hwsec, &old_database)) {
    LOG(ERROR) << __func__ << ":Failed to unseal attestation database.";
    return false;
  }
  *delegate = LegacyDelegationToAuthDelegate(old_database.delegate());
  return true;
}

bool UnsealOwnerPasswordFromSerializedTpmStatus(
    const brillo::SecureBlob& serialized_tpm_status,
    const hwsec::LocalDataMigrationFrontend* hwsec,
    brillo::SecureBlob* owner_password) {
  CHECK(owner_password != nullptr);
  CHECK(hwsec != nullptr);

  LegacyTpmStatus tpm_status;
  if (!tpm_status.ParseFromArray(serialized_tpm_status.data(),
                                 serialized_tpm_status.size())) {
    LOG(ERROR) << __func__ << ": Failed to parse tpm status.";
    return false;
  }
  if (!tpm_status.owner_password().empty()) {
    ASSIGN_OR_RETURN(
        *owner_password,
        hwsec->Unseal(brillo::BlobFromString(tpm_status.owner_password())),
        _.WithStatus<TPMError>("Failed to unseal owner password")
            .LogError()
            .As(false));
  }
  return true;
}

bool LocalDataMigrator::MigrateAuthDelegateIfNeeded(
    const base::FilePath& database_path,
    const hwsec::LocalDataMigrationFrontend* hwsec,
    LocalData* local_data,
    bool* has_migrated) {
  CHECK(hwsec != nullptr);
  CHECK(local_data != nullptr);
  CHECK(has_migrated != nullptr);

  *has_migrated = false;
  auto auth_delegate = local_data->mutable_owner_delegate();
  if ((!auth_delegate->blob().empty() && !auth_delegate->secret().empty()) ||
      !PathExists(database_path)) {
    return true;
  }
  std::string sealed_database;
  if (!ReadFileToString(database_path, &sealed_database)) {
    LOG(ERROR) << __func__ << ": Failed to read attestation database from "
               << database_path.value();
    return false;
  }
  if (!MigrateAuthDelegate(brillo::SecureBlob(sealed_database), hwsec,
                           auth_delegate)) {
    LOG(ERROR) << __func__ << ": Failed to migrate auth delegate from "
               << database_path.value();
    return false;
  }
  *has_migrated = !local_data->owner_delegate().blob().empty() &&
                  !local_data->owner_delegate().secret().empty();
  return true;
}

bool LocalDataMigrator::MigrateOwnerPasswordIfNeeded(
    const base::FilePath& tpm_status_path,
    const hwsec::LocalDataMigrationFrontend* hwsec,
    LocalData* local_data,
    bool* has_migrated) {
  CHECK(local_data != nullptr);
  CHECK(has_migrated != nullptr);

  *has_migrated = false;
  if (!local_data->owner_password().empty() || !PathExists(tpm_status_path)) {
    return true;
  }
  std::string serialized_tpm_status;
  if (!ReadFileToString(tpm_status_path, &serialized_tpm_status)) {
    LOG(ERROR) << __func__ << ": Failed to read tpm status from "
               << tpm_status_path.value();
    return false;
  }
  brillo::SecureBlob owner_password;
  if (!UnsealOwnerPasswordFromSerializedTpmStatus(
          brillo::SecureBlob(serialized_tpm_status), hwsec, &owner_password)) {
    LOG(ERROR) << __func__ << ": Failed to parse tpm status from "
               << tpm_status_path.value();
    return false;
  }
  local_data->set_owner_password(owner_password.data(), owner_password.size());
  *has_migrated = !local_data->owner_password().empty();
  return true;
}

bool LocalDataMigrator::PathExists(const base::FilePath& path) {
  return base::PathExists(path);
}

bool LocalDataMigrator::ReadFileToString(const base::FilePath& path,
                                         std::string* content) {
  return base::ReadFileToString(path, content);
}

}  // namespace tpm_manager
