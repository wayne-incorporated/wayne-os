// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/libscrypt_compat.h"

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <base/bits.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/sys_byteorder.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>

#include "libhwsec-foundation/crypto/aes.h"
#include "libhwsec-foundation/crypto/hmac.h"
#include "libhwsec-foundation/crypto/sha.h"

namespace hwsec_foundation {

namespace {

constexpr size_t kLibScryptHeaderSize = 96;

constexpr size_t kLibScryptSubHeaderSize = 48;

constexpr size_t kLibScryptHeaderBytesToHMAC = 64;

constexpr char kLibScryptHeaderMagic[] = "scrypt";

// Bytes 33-64 of the derived key are used for the HMAC key.
constexpr size_t kLibScryptHMACKeyOffset = 32;

constexpr size_t kLibScryptHMACSize = 32;

constexpr size_t kLibScryptIVSize = 16;

// libscrypt places data into a uint8_t[96] array in C style. This lays it out
// as a more readable struct, but it must be tightly packed to be compatible
// with the array.
#pragma pack(push, 1)
struct LibScryptHeader {
  // This is always "scrypt".
  char magic[6];
  // This is set to 0.
  uint8_t header_reserved_byte;
  // The log base 2 of the N-factor (i.e. 10 for 1024).
  uint8_t log_n;
  // The r and p params used to generate this key.
  uint32_t r_factor;
  uint32_t p_factor;
  // A salt which is unique to each encryption. Note that this is a bit odd and
  // in new scrypt code it's better to use a unique *nonce* in the AES
  // encryption.
  uint8_t salt[32];
  // This is a checksum of the first 48 bytes of the header (all fields up to
  // and including the salt).
  uint8_t check_sum[16];
  // This is an HMAC over the first 64 bytes of the header (all fields up to and
  // including the check_sum). Why there is a check_sum and an HMAC is
  // confusing, since they cover the same data. But the key given to the HMAC is
  // the last 32 bytes of the |derived_key|, and so it verifies that the
  // password is the proper passsord for this encrypted blob.
  uint8_t signature[kLibScryptHMACSize];
};
#pragma pack(pop)

static_assert(sizeof(LibScryptHeader) == kLibScryptHeaderSize,
              "LibScryptHeader struct is packed wrong and will not be byte "
              "compatible with existing data");

// This generates the header which is specific to libscrypt. It's inserted at
// the beginning |output|.
void GenerateHeader(const brillo::SecureBlob& salt,
                    const brillo::SecureBlob& derived_key,
                    const ScryptParameters& params,
                    LibScryptHeader* header_struct) {
  DCHECK_EQ(kLibScryptSaltSize, salt.size());

  *header_struct = {
      {'s', 'c', 'r', 'y', 'p', 't'},
      0,
      static_cast<uint8_t>(base::bits::Log2Ceiling(params.n_factor)),
      base::ByteSwap(params.r_factor),
      base::ByteSwap(params.p_factor)};

  memcpy(&header_struct->salt, salt.data(), sizeof(header_struct->salt));

  // Add the header check sum.
  uint8_t* header_ptr = reinterpret_cast<uint8_t*>(header_struct);
  brillo::Blob header_blob_to_hash(header_ptr,
                                   header_ptr + kLibScryptSubHeaderSize);
  brillo::Blob sha = Sha256(header_blob_to_hash);
  memcpy(&header_struct->check_sum[0], sha.data(),
         sizeof(header_struct->check_sum));

  // Add the header signature (used for verifying the passsword).
  brillo::SecureBlob key_hmac(derived_key.begin() + kLibScryptHMACKeyOffset,
                              derived_key.end());
  brillo::Blob data_to_hmac(header_ptr,
                            header_ptr + kLibScryptHeaderBytesToHMAC);
  brillo::SecureBlob hmac = HmacSha256(key_hmac, data_to_hmac);
  memcpy(&header_struct->signature[0], hmac.data(),
         sizeof(header_struct->signature));
}

bool VerifyDerivedKey(const brillo::SecureBlob& encrypted_blob,
                      const brillo::SecureBlob& derived_key) {
  const LibScryptHeader* header =
      reinterpret_cast<const LibScryptHeader*>(encrypted_blob.data());
  const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(header);

  // Verify the password.
  brillo::SecureBlob key_hmac(derived_key.begin() + kLibScryptHMACKeyOffset,
                              derived_key.end());
  brillo::Blob data_to_hmac(header_ptr,
                            header_ptr + kLibScryptHeaderBytesToHMAC);
  brillo::SecureBlob hmac = HmacSha256(key_hmac, data_to_hmac);
  if (brillo::SecureMemcmp(header->signature, hmac.data(),
                           kLibScryptHMACSize) != 0) {
    LOG(ERROR) << "hmac verification failed.";
    return false;
  }

  return true;
}

}  // namespace

// static
bool LibScryptCompat::Encrypt(const brillo::SecureBlob& derived_key,
                              const brillo::SecureBlob& salt,
                              const brillo::SecureBlob& data_to_encrypt,
                              const ScryptParameters& params,
                              brillo::SecureBlob* encrypted_data) {
  encrypted_data->resize(data_to_encrypt.size() + kLibScryptHeaderSize +
                         kLibScryptHMACSize);

  LibScryptHeader header_struct;
  GenerateHeader(salt, derived_key, params, &header_struct);
  memcpy(encrypted_data->data(), &header_struct, sizeof(header_struct));

  brillo::SecureBlob aes_key(derived_key.begin(),
                             derived_key.end() - kLibScryptHMACKeyOffset);
  // libscrypt uses a 0 IV for every message. This is safe _ONLY_ because
  // libscrypt mixes the passphrase with a new salt, generating a new derived
  // key, FOR EACH ENCRYPTION. DO NOT CALL THIS ENCRYPTION method multiple times
  // with the same key, it is only safe under this limited circumstances.
  brillo::SecureBlob iv(kLibScryptIVSize, 0);
  brillo::SecureBlob aes_ciphertext;

  if (!AesEncryptSpecifyBlockMode(data_to_encrypt, 0, data_to_encrypt.size(),
                                  aes_key, iv, PaddingScheme::kPaddingStandard,
                                  BlockMode::kCtr, &aes_ciphertext)) {
    LOG(ERROR) << "AesEncryptSpecifyBlockMode failed.";
    return false;
  }
  memcpy(encrypted_data->data() + sizeof(header_struct), aes_ciphertext.data(),
         aes_ciphertext.size());

  brillo::SecureBlob key_hmac(derived_key.begin() + kLibScryptHMACKeyOffset,
                              derived_key.end());
  brillo::Blob data_to_hmac(
      encrypted_data->begin(),
      encrypted_data->begin() + aes_ciphertext.size() + kLibScryptHeaderSize);
  brillo::SecureBlob hmac = HmacSha256(key_hmac, data_to_hmac);

  memcpy(encrypted_data->data() + sizeof(header_struct) + aes_ciphertext.size(),
         hmac.data(), kLibScryptHMACSize);

  return true;
}

// static
bool LibScryptCompat::ParseHeader(const brillo::SecureBlob& encrypted_blob,
                                  ScryptParameters* out_params,
                                  brillo::SecureBlob* salt) {
  if (encrypted_blob.size() < kLibScryptHeaderSize + kLibScryptHMACSize) {
    LOG(ERROR) << "Incomplete header present.";
    return false;
  }

  const LibScryptHeader* header =
      reinterpret_cast<const LibScryptHeader*>(encrypted_blob.data());
  if (brillo::SecureMemcmp(header->magic, kLibScryptHeaderMagic,
                           strlen(kLibScryptHeaderMagic)) != 0) {
    LOG(ERROR) << "wrong header text present";
    return false;
  }

  if (header->header_reserved_byte != 0) {
    LOG(ERROR) << "Wrong reserved byte present";
    return false;
  }

  // Verify the header checksum before returning any information.
  const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(header);
  brillo::Blob header_blob_to_hash(header_ptr,
                                   header_ptr + kLibScryptSubHeaderSize);
  brillo::Blob sha = Sha256(header_blob_to_hash);
  if (brillo::SecureMemcmp(sha.data(), header->check_sum,
                           sizeof(header->check_sum)) != 0) {
    LOG(ERROR) << "Wrong checksum present.";
    return false;
  }

  // Now parse the parameters.
  if (header->log_n < 1 || header->log_n > 63) {
    LOG(ERROR) << "Invalid logN present in header.";
    return false;
  }

  out_params->n_factor = static_cast<uint64_t>(1) << header->log_n;
  out_params->r_factor = base::ByteSwap(header->r_factor);
  out_params->p_factor = base::ByteSwap(header->p_factor);
  salt->assign(header->salt, header->salt + kLibScryptSaltSize);

  return true;
}

// static
bool LibScryptCompat::Decrypt(const brillo::SecureBlob& encrypted_data,
                              const brillo::SecureBlob& derived_key,
                              brillo::SecureBlob* decrypted_data) {
  if (!VerifyDerivedKey(encrypted_data, derived_key))
    return false;

  // lib scrypt appends an HMAC.
  brillo::SecureBlob key_hmac(derived_key.begin() + kLibScryptHMACKeyOffset,
                              derived_key.end());
  brillo::Blob data_to_hmac(encrypted_data.begin(),
                            encrypted_data.end() - kLibScryptHMACSize);
  brillo::SecureBlob hmac = HmacSha256(key_hmac, data_to_hmac);
  brillo::SecureBlob hmac_from_blob(encrypted_data.end() - kLibScryptHMACSize,
                                    encrypted_data.end());
  if (brillo::SecureMemcmp(hmac.data(), hmac_from_blob.data(),
                           kLibScryptHMACSize) != 0) {
    return false;
  }

  brillo::SecureBlob aes_key(derived_key.begin(),
                             derived_key.end() - kLibScryptHMACKeyOffset);
  // libscrypt uses a 0 IV for every message. This is safe _ONLY_ because
  // libscrypt mixes the passphrase with a new salt, generating a new derived
  // key, FOR EACH ENCRYPTION.
  brillo::SecureBlob iv(kLibScryptIVSize, 0);
  brillo::SecureBlob data_to_decrypt(
      encrypted_data.begin() + kLibScryptHeaderSize,
      encrypted_data.end() - kLibScryptHMACSize);

  if (!AesDecryptSpecifyBlockMode(data_to_decrypt, 0, data_to_decrypt.size(),
                                  aes_key, iv, PaddingScheme::kPaddingStandard,
                                  BlockMode::kCtr, decrypted_data)) {
    LOG(ERROR) << "AesDecryptSpecifyBlockMode failed.";
    return false;
  }
  return true;
}

}  // namespace hwsec_foundation
