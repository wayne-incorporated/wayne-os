// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_ELLIPTIC_CURVE_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_ELLIPTIC_CURVE_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// A light-weight C++ wrapper for OpenSSL Elliptic Curve primitives.
class HWSEC_FOUNDATION_EXPORT EllipticCurve final {
 public:
  // Currently only most common prime curves are supported, but the interface
  // can be extended to any OpenSSL supported curve if needed.
  enum class CurveType { kPrime256, kPrime384, kPrime521 };

  // Creates an elliptic curve. Returns `std::nullopt` if error occurred.
  // Context is only used during creation of the curve and does not have to
  // outlive the curve instance (it is not stored in a curve object).
  static std::optional<EllipticCurve> Create(CurveType curve, BN_CTX* context);

  // Non-copyable, but movable.
  EllipticCurve(EllipticCurve&& other) = default;
  EllipticCurve& operator=(EllipticCurve&& other) = default;

  ~EllipticCurve();

  // Returns true if point is on a curve (including point at infinity).
  bool IsPointValid(const EC_POINT& point, BN_CTX* context) const;

  // Returns true if point is at infinity.
  bool IsPointAtInfinity(const EC_POINT& point) const;

  // Returns true if point is on a curve and finite (not at infinity).
  bool IsPointValidAndFinite(const EC_POINT& point, BN_CTX* context) const;

  // Calculate the inverse of the supplied `point`. The result is placed back in
  // `point`.
  bool InvertPoint(EC_POINT* point, BN_CTX* context) const;

  // Returns scalar size in bytes of a curve order.
  int ScalarSizeInBytes() const;

  // Returns true if scalar is inside the curve order.
  bool IsScalarValid(const BIGNUM& scalar) const;

  // Returns field element (affine coordinate) size in bytes.
  int AffineCoordinateSizeInBytes() const;

  // Returns affine coordinates of a given `point`: when `x` is non-null it's
  // assigned to the x coordinate, and when `y` is non-null it's assigned to the
  // y coordinate.
  bool GetAffineCoordinates(const EC_POINT& point,
                            BN_CTX* context,
                            BIGNUM* x,
                            BIGNUM* y) const;

  // Allocates the EC_POINT object, which is in a valid but unspecified state.
  // Returns nullptr on failure.
  crypto::ScopedEC_POINT CreatePoint() const;

  // Generates random non-zero scalar of the elliptic curve order. Returns
  // nullptr if error occurred.
  crypto::ScopedBIGNUM RandomNonZeroScalar(BN_CTX* context) const;

  // Performs addition modulo order. Returns nullptr if error occurred.
  crypto::ScopedBIGNUM ModAdd(const BIGNUM& a,
                              const BIGNUM& b,
                              BN_CTX* context) const;

  // Returns true if two points are equal.
  bool AreEqual(const EC_POINT& point1,
                const EC_POINT& point2,
                BN_CTX* context) const;

  // Performs point by scalar multiplication. Input point must be on a curve.
  // It is required that scalar is in the range of [0..curve order-1].
  // Returns nullptr if error occurred.
  crypto::ScopedEC_POINT Multiply(const EC_POINT& point,
                                  const BIGNUM& scalar,
                                  BN_CTX* context) const;

  // Performs multiplication with generator. Expects scalar to be in the range
  // of [-curve order..curve order-1]. Return nullptr if error occurred.
  crypto::ScopedEC_POINT MultiplyWithGenerator(const BIGNUM& scalar,
                                               BN_CTX* context) const;

  // Performs point addition. Input points must be on a curve.
  // If two points are equal, the addition will perform doubling: P + P = 2P.
  // The result is a point on a curve or point at infinity e.g. P+(-P) = inf.
  // Returns nullptr if error occurred.
  crypto::ScopedEC_POINT Add(const EC_POINT& point1,
                             const EC_POINT& point2,
                             BN_CTX* context) const;

  // Returns a EC_KEY object with public key set to provided `point`.
  // Returns nullptr if error occurred.
  crypto::ScopedEC_KEY PointToEccKey(const EC_POINT& point) const;

  // Converts the ECC public key in provided `key` to the DER-encoded X.509
  // SubjectPublicKeyInfo format. Returns false if error occurred, otherwise
  // stores resulting blob in `result`.
  bool EncodeToSpkiDer(const crypto::ScopedEC_KEY& key,
                       brillo::SecureBlob* result,
                       BN_CTX* context) const;

  // Converts `blob` from DER encoded SubjectPublicKeyInfo format to ECC public
  // key and returns it as EC_POINT. Returns nullptr if error occurred.
  crypto::ScopedEC_POINT DecodeFromSpkiDer(
      const brillo::SecureBlob& public_key_spki_der, BN_CTX* context) const;

  // Generates EC_KEY. This method should be preferred over generating private
  // and public key separately, that is, private key using `RandomNonZeroScalar`
  // and public key by multiplying private key with generator, but the result
  // should be equivalent. Returns nullptr if error occurred.
  crypto::ScopedEC_KEY GenerateKey(BN_CTX* context) const;

  // Generates a pair of public (in DER-encoded X.509
  // SubjectPublicKeyInfo format) and private keys. Returns false if error
  // occurred.
  bool GenerateKeysAsSecureBlobs(brillo::SecureBlob* public_key_spki_der,
                                 brillo::SecureBlob* private_key,
                                 BN_CTX* context) const;

  // Returns curve order. This should be used only for testing.
  const BIGNUM* GetOrderForTesting() const { return order_.get(); }

  // Returns point at infinity or nullptr if error occurred.
  // This should be used only for testing.
  crypto::ScopedEC_POINT PointAtInfinityForTesting() const;

  // Returns group.
  const EC_GROUP* GetGroup() const { return group_.get(); }

  // Returns curve type.
  CurveType GetCurveType() const { return curve_; }

 private:
  // Constructor is private. A user of the class should use `Create` method
  // instead.
  explicit EllipticCurve(CurveType curve,
                         crypto::ScopedEC_GROUP group,
                         crypto::ScopedBIGNUM order);

  CurveType curve_;
  crypto::ScopedEC_GROUP group_;
  crypto::ScopedBIGNUM order_;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_ELLIPTIC_CURVE_H_
