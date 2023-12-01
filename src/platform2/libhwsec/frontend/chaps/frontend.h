// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CHAPS_FRONTEND_H_
#define LIBHWSEC_FRONTEND_CHAPS_FRONTEND_H_

#include <string>
#include <vector>

#include <absl/container/flat_hash_set.h>
#include <brillo/secure_blob.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/backend/signing.h"
#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

struct ChapsSealedData {
  // The sealed data.
  brillo::Blob key_blob;

  // Backward compatibility data.
  brillo::Blob encrypted_data;
};

class ChapsFrontend : public Frontend {
 public:
  using CreateKeyResult = KeyManagement::CreateKeyResult;
  using GetRandomSecureBlobCallback =
      base::OnceCallback<void(StatusOr<brillo::SecureBlob>)>;
  using SealDataCallback = base::OnceCallback<void(StatusOr<ChapsSealedData>)>;
  using UnsealDataCallback =
      base::OnceCallback<void(StatusOr<brillo::SecureBlob>)>;

  enum class AllowSoftwareGen : bool {
    kNotAllow = false,
    kAllow = true,
  };

  enum class AllowSign : bool {
    kNotAllow = false,
    kAllow = true,
  };

  enum class AllowDecrypt : bool {
    kNotAllow = false,
    kAllow = true,
  };

  ~ChapsFrontend() override = default;

  // Gets the TPM family of GSC/TPM.
  // 0x312E3200 = TPM1.2
  // 0x322E3000 = TPM2.0
  virtual StatusOr<uint32_t> GetFamily() const = 0;

  // Is the security module enabled or not.
  virtual StatusOr<bool> IsEnabled() const = 0;

  // Is the security module ready to use or not.
  virtual StatusOr<bool> IsReady() const = 0;

  // Generates random blob with |size|.
  virtual StatusOr<brillo::Blob> GetRandomBlob(size_t size) const = 0;

  // Generates random secure blob with |size|.
  virtual StatusOr<brillo::SecureBlob> GetRandomSecureBlob(
      size_t size) const = 0;

  // Return supports |modulus_bits| or not. |modulus_bits| is the RSA
  // key/modulus size.
  virtual Status IsRSAModulusSupported(uint32_t modulus_bits) const = 0;

  // Return supports |curve_nid| or not. |curve_nid| is the NID of OpenSSL.
  // TPM 1.2 doesn't support ECC.
  // TPM 2.0 current only support P-256 curve (NID_X9_62_prime256v1).
  virtual Status IsECCurveSupported(int nid) const = 0;

  // Generates an RSA key pair and stores it in the hardware backed security
  // module.
  //   modulus_bits - The size of the key to be generated (usually 2048).
  //   public_exponent - The RSA public exponent (usually {1, 0, 1} which is
  //                     65537).
  //   auth_value - Authorization data which will be associated with the key.
  //   allow_soft_gen - Allow to generate the key in the software or not.
  virtual StatusOr<CreateKeyResult> GenerateRSAKey(
      int modulus_bits,
      const brillo::Blob& public_exponent,
      const brillo::SecureBlob& auth_value,
      AllowSoftwareGen allow_soft_gen,
      AllowDecrypt allow_decrypt,
      AllowSign allow_sign) const = 0;

  // Retrieves the public components of an RSA key pair.
  virtual StatusOr<RSAPublicInfo> GetRSAPublicKey(Key key) const = 0;

  // Generates an ECC key pair in the hardware backed security module.
  //   nid - the OpenSSL NID for the curve.
  //   auth_value - Authorization data which will be associated with the key.
  virtual StatusOr<CreateKeyResult> GenerateECCKey(
      int nid,
      const brillo::SecureBlob& auth_value,
      AllowDecrypt allow_decrypt,
      AllowSign allow_sign) const = 0;

  // Retrieves the public point of ECC key pair.
  virtual StatusOr<ECCPublicInfo> GetECCPublicKey(Key key) const = 0;

  // Wraps an RSA key pair with the hardware backed security module.
  //   exponent - The RSA public exponent (e).
  //   modulus - The RSA modulus (n).
  //   prime_factor - One of the prime factors of the modulus (p or q).
  //   auth_value - Authorization data which will be associated with the key.
  virtual StatusOr<CreateKeyResult> WrapRSAKey(
      const brillo::Blob& exponent,
      const brillo::Blob& modulus,
      const brillo::SecureBlob& prime_factor,
      const brillo::SecureBlob& auth_value,
      AllowDecrypt allow_decrypt,
      AllowSign allow_sign) const = 0;

  // Wraps an ECC key pair with the hardware backed security module.
  //   curve_nid - The OpenSSL NID of the ECC curve.
  //   public_point_x - The x coordinate of ECC public key point on the curve.
  //   public_point_y - The y coordinate of ECC public key point on the curve.
  //   private_value - The ECC private key value.
  //   prime_factor - One of the prime factors of the modulus (p or q).
  //   auth_value - Authorization data which will be associated with the key.
  virtual StatusOr<CreateKeyResult> WrapECCKey(
      int curve_nid,
      const brillo::Blob& public_point_x,
      const brillo::Blob& public_point_y,
      const brillo::SecureBlob& private_value,
      const brillo::SecureBlob& auth_value,
      AllowDecrypt allow_decrypt,
      AllowSign allow_sign) const = 0;

  // Loads a key by blob into the hardware backed security module.
  //   key_blob - The key blob as provided by GenerateKey or WrapRSAKey.
  //   auth_value - Authorization data for the key.
  // Returns true on success.
  virtual StatusOr<ScopedKey> LoadKey(
      const brillo::Blob& key_blob,
      const brillo::SecureBlob& auth_value) const = 0;

  // Performs a 'unbind' operation using the TSS_ES_RSAESPKCSV15 scheme. This
  // effectively performs PKCS #1 v1.5 RSA decryption (using PKCS #1 'type 2'
  // padding).
  //   key - The key handle that derived from ScopedKey.
  //   ciphertext - Data to be decrypted.
  virtual StatusOr<brillo::SecureBlob> Unbind(
      Key key, const brillo::Blob& ciphertext) const = 0;

  // Generates a digital signature.
  //   key - The key handle that derived from ScopedKey.
  //   data - The data to sign.
  //   options - The detail options for the signing mechanism and parameters.
  // Returns true on success.
  virtual StatusOr<brillo::Blob> Sign(Key key,
                                      const brillo::Blob& data,
                                      const SigningOptions& options) const = 0;

  // Seals the data to hardware backed security module.
  //   unsealed_data - The data that needs to be sealed.
  //   auth_value - Authorization data which will be associated with the sealed
  //                data.
  virtual StatusOr<ChapsSealedData> SealData(
      const brillo::SecureBlob& unsealed_data,
      const brillo::SecureBlob& auth_value) const = 0;

  // Unseals the data from hardware backed security module.
  //   sealed_data - The data returned by SealData.
  //   auth_value - Authorization data that associated with the sealed data.
  virtual StatusOr<brillo::SecureBlob> UnsealData(
      const ChapsSealedData& sealed_data,
      const brillo::SecureBlob& auth_value) const = 0;

  // Asynchronous version of GetRandomSecureBlob.
  virtual void GetRandomSecureBlobAsync(
      size_t size, GetRandomSecureBlobCallback callback) const = 0;

  // Asynchronous version of SealData.
  virtual void SealDataAsync(const brillo::SecureBlob& unsealed_data,
                             const brillo::SecureBlob& auth_value,
                             SealDataCallback callback) const = 0;

  // Asynchronous version of UnsealData.
  virtual void UnsealDataAsync(const ChapsSealedData& sealed_data,
                               const brillo::SecureBlob& auth_value,
                               UnsealDataCallback callback) const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CHAPS_FRONTEND_H_
