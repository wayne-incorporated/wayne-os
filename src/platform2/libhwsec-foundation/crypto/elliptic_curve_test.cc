// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/elliptic_curve.h"

#include <optional>

#include "libhwsec-foundation/crypto/big_num_util.h"
#include "libhwsec-foundation/crypto/error_util.h"

#include <gtest/gtest.h>

#include <base/logging.h>

namespace hwsec_foundation {

namespace {

constexpr EllipticCurve::CurveType kCurve = EllipticCurve::CurveType::kPrime256;
constexpr int kScalarSizeInBytes = 32;
constexpr int kFieldElementSizeInBytes = 32;
// SPKI DER formatted (ecPublicKey, prime256v1) public point with valid point
// which is not on curve.
const char kSpkiDerPoint[] =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200040102030405060708090A"
    "0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"
    "303132333435363738393A3B3C3D3E3F40";

brillo::SecureBlob CreateBogusPointSpkiDer() {
  brillo::SecureBlob spki_der;
  if (!brillo::SecureBlob::HexStringToSecureBlob(kSpkiDerPoint, &spki_der)) {
    ADD_FAILURE() << "Failed to convert hex to SecureBlob";
    return brillo::SecureBlob();
  }

  return spki_der;
}

// Returns a EC_KEY object with public key set to provided `point`. Unlike
// `EllipticCurve::PointToEccKey`, doesn't check if the key is valid.
crypto::ScopedEC_KEY PointToEccKey(const EC_POINT& point,
                                   const EC_GROUP* group) {
  crypto::ScopedEC_Key key(EC_KEY_new());
  if (!key) {
    ADD_FAILURE() << "Failed to allocate EC_KEY structure: "
                  << GetOpenSSLErrors();
    return nullptr;
  }

  if (EC_KEY_set_group(key.get(), group) != 1) {
    ADD_FAILURE() << "Failed to set EC group: " << GetOpenSSLErrors();
    return nullptr;
  }

  if (!EC_KEY_set_public_key(key.get(), &point)) {
    ADD_FAILURE() << "Failed to set public key: " << GetOpenSSLErrors();
    return nullptr;
  }

  return key;
}

}  // namespace

class EllipticCurveTest : public testing::Test {
 public:
  void SetUp() override {
    context_ = CreateBigNumContext();
    ASSERT_TRUE(context_);
    ec_ = EllipticCurve::Create(kCurve, context_.get());
    ASSERT_TRUE(ec_);
  }

  // Creates point as generator multiplied by scalar_value.
  // Returns nullptr if error occurred.
  crypto::ScopedEC_POINT CreatePoint(BN_ULONG scalar_value) {
    crypto::ScopedBIGNUM scalar = BigNumFromValue(scalar_value);
    if (!scalar) {
      LOG(ERROR) << "Failed to create BIGNUM structure";
      return nullptr;
    }
    return ec_->MultiplyWithGenerator(*scalar, context_.get());
  }

  // Creates invalid point that is not on a curve.
  // Returns nullptr if error occurred.
  crypto::ScopedEC_POINT CreateInvalidPoint() {
    crypto::ScopedEC_POINT point = ec_->PointAtInfinityForTesting();
    if (!point) {
      LOG(ERROR) << "Failed to create point at infinity";
      return nullptr;
    }

    // Set point to some coordinates that are not on a curve.
    crypto::ScopedBIGNUM x = BigNumFromValue(123u);
    if (!x) {
      LOG(ERROR) << "Failed to create BIGNUM structure";
      return nullptr;
    }
    crypto::ScopedBIGNUM y = BigNumFromValue(321u);
    if (!y) {
      LOG(ERROR) << "Failed to create BIGNUM structure";
      return nullptr;
    }

    // Set affine coordinates outside of the curve. Assume the method will fail,
    // but it should still initialize the point.
    if (EC_POINT_set_affine_coordinates(ec_->GetGroup(), point.get(), x.get(),
                                        y.get(), context_.get()) == 1) {
      LOG(ERROR) << "Failed to set affine coords for invalid point";
      return nullptr;
    }

    // Capture OpenSSL error from error stack.
    std::string error = GetOpenSSLErrors();
    if (error.find("EC_POINT_set_affine_coordinates:point is not on curve") ==
        std::string::npos) {
      LOG(ERROR) << "Failed to create invalid point";
      return nullptr;
    }

    // Verify that the point is not at infinity anymore, so it was indeed set,
    // but it's not on a curve.
    if (ec_->IsPointAtInfinity(*point) ||
        ec_->IsPointValid(*point, context_.get())) {
      LOG(ERROR) << "Failed to create invalid point";
      return nullptr;
    }
    return point;
  }

 protected:
  ScopedBN_CTX context_;
  std::optional<EllipticCurve> ec_;
};

TEST_F(EllipticCurveTest, GetCurveType) {
  std::optional<EllipticCurve> ec_256 = EllipticCurve::Create(
      EllipticCurve::CurveType::kPrime256, context_.get());
  ASSERT_TRUE(ec_256);
  EXPECT_EQ(ec_256->GetCurveType(), EllipticCurve::CurveType::kPrime256);

  std::optional<EllipticCurve> ec_384 = EllipticCurve::Create(
      EllipticCurve::CurveType::kPrime384, context_.get());
  ASSERT_TRUE(ec_384);
  EXPECT_EQ(ec_384->GetCurveType(), EllipticCurve::CurveType::kPrime384);

  std::optional<EllipticCurve> ec_521 = EllipticCurve::Create(
      EllipticCurve::CurveType::kPrime521, context_.get());
  ASSERT_TRUE(ec_521);
  EXPECT_EQ(ec_521->GetCurveType(), EllipticCurve::CurveType::kPrime521);
}

TEST_F(EllipticCurveTest, ScalarAndAffineCoordinateSizeInBytes) {
  EXPECT_EQ(ec_->ScalarSizeInBytes(), kScalarSizeInBytes);
  EXPECT_EQ(ec_->AffineCoordinateSizeInBytes(), kFieldElementSizeInBytes);
}

TEST_F(EllipticCurveTest, PointAtInfinity) {
  crypto::ScopedEC_POINT point = ec_->PointAtInfinityForTesting();
  ASSERT_TRUE(point);
  EXPECT_TRUE(ec_->IsPointValid(*point, context_.get()));
  EXPECT_TRUE(ec_->IsPointAtInfinity(*point));
}

TEST_F(EllipticCurveTest, RandomNonZeroScalar) {
  // Generates random secret. Note that this is non-deterministic,
  // so we just check if the output is smaller than curve order
  // and non-zero.
  crypto::ScopedBIGNUM secret = ec_->RandomNonZeroScalar(context_.get());
  ASSERT_TRUE(secret);
  EXPECT_EQ(BN_cmp(secret.get(), ec_->GetOrderForTesting()), -1);
  EXPECT_EQ(BN_is_zero(secret.get()), 0);
}

TEST_F(EllipticCurveTest, SubjectPublicKeyInfoConversions) {
  crypto::ScopedEC_KEY key = ec_->GenerateKey(context_.get());
  ASSERT_TRUE(key);
  // Encode the public key:
  brillo::SecureBlob spki_der_point_blob;
  ASSERT_TRUE(ec_->EncodeToSpkiDer(key, &spki_der_point_blob, context_.get()));
  // Decode the public key:
  crypto::ScopedEC_POINT spki_der_decoded_key =
      ec_->DecodeFromSpkiDer(spki_der_point_blob, context_.get());
  // Compare the keys:
  EXPECT_TRUE(ec_->AreEqual(*EC_KEY_get0_public_key(key.get()),
                            *spki_der_decoded_key, context_.get()));

  // Test conversions of invalid or infinite points.
  brillo::SecureBlob point_blob;
  crypto::ScopedEC_POINT invalid_point = CreateInvalidPoint();
  ASSERT_TRUE(invalid_point);
  crypto::ScopedEC_KEY invalid_point_key =
      PointToEccKey(*invalid_point, ec_->GetGroup());
  ASSERT_TRUE(invalid_point_key);
  EXPECT_FALSE(
      ec_->EncodeToSpkiDer(invalid_point_key, &point_blob, context_.get()));

  crypto::ScopedEC_POINT point_at_inf = ec_->PointAtInfinityForTesting();
  ASSERT_TRUE(point_at_inf);
  crypto::ScopedEC_KEY point_at_inf_key =
      PointToEccKey(*point_at_inf, ec_->GetGroup());
  ASSERT_TRUE(point_at_inf_key);
  EXPECT_FALSE(
      ec_->EncodeToSpkiDer(point_at_inf_key, &point_blob, context_.get()));

  crypto::ScopedEC_POINT decoded_key =
      ec_->DecodeFromSpkiDer(brillo::SecureBlob("not_a_point"), context_.get());
  EXPECT_FALSE(decoded_key);
  decoded_key =
      ec_->DecodeFromSpkiDer(CreateBogusPointSpkiDer(), context_.get());
  EXPECT_FALSE(decoded_key);
}

TEST_F(EllipticCurveTest, PointToEccKey) {
  crypto::ScopedEC_KEY key = ec_->GenerateKey(context_.get());
  ASSERT_TRUE(key);
  const EC_POINT* public_key = EC_KEY_get0_public_key(key.get());
  ASSERT_TRUE(public_key);

  crypto::ScopedEC_KEY key_1 = ec_->PointToEccKey(*public_key);
  ASSERT_TRUE(key_1);
  const EC_POINT* public_key_1 = EC_KEY_get0_public_key(key_1.get());
  ASSERT_TRUE(public_key_1);

  EXPECT_TRUE(ec_->AreEqual(*public_key, *public_key_1, context_.get()));

  // Test conversions of invalid or infinite points.
  brillo::SecureBlob point_blob;
  crypto::ScopedEC_POINT invalid_point = CreateInvalidPoint();
  ASSERT_TRUE(invalid_point);
  crypto::ScopedEC_KEY invalid_point_key = ec_->PointToEccKey(*invalid_point);
  EXPECT_FALSE(invalid_point_key);

  crypto::ScopedEC_POINT point_at_inf = ec_->PointAtInfinityForTesting();
  ASSERT_TRUE(point_at_inf);
  crypto::ScopedEC_KEY point_at_inf_key = ec_->PointToEccKey(*point_at_inf);
  EXPECT_FALSE(point_at_inf_key);
}

TEST_F(EllipticCurveTest, PointToEccKeySubjectPublicKeyInfoConversions) {
  crypto::ScopedEC_KEY key = ec_->GenerateKey(context_.get());
  ASSERT_TRUE(key);
  const EC_POINT* public_key = EC_KEY_get0_public_key(key.get());
  ASSERT_TRUE(public_key);
  crypto::ScopedEC_KEY key_1 = ec_->PointToEccKey(*public_key);
  ASSERT_TRUE(key_1);

  brillo::SecureBlob spki_der_public_key, spki_der_public_key_1;
  ASSERT_TRUE(ec_->EncodeToSpkiDer(key, &spki_der_public_key, context_.get()));
  ASSERT_TRUE(
      ec_->EncodeToSpkiDer(key_1, &spki_der_public_key_1, context_.get()));
  EXPECT_EQ(spki_der_public_key, spki_der_public_key_1);
}

TEST_F(EllipticCurveTest, Add) {
  crypto::ScopedEC_POINT point1 = CreatePoint(1u);
  ASSERT_TRUE(point1);
  crypto::ScopedEC_POINT point2 = CreatePoint(2u);
  ASSERT_TRUE(point2);
  crypto::ScopedEC_POINT point3 = CreatePoint(3u);
  ASSERT_TRUE(point3);

  crypto::ScopedEC_POINT result = ec_->Add(*point1, *point2, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->AreEqual(*result, *point3, context_.get()));

  // Double the point.
  result = ec_->Add(*point1, *point1, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->AreEqual(*result, *point2, context_.get()));

  // Add point to its inverse.
  crypto::ScopedEC_POINT inv_point3 = CreatePoint(3u);
  ASSERT_EQ(EC_POINT_invert(ec_->GetGroup(), inv_point3.get(), context_.get()),
            1);
  result = ec_->Add(*point3, *inv_point3, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->IsPointAtInfinity(*result));

  // Check if inverse of nG is (order-n)*G.
  crypto::ScopedBIGNUM order_sub_3 = BigNumFromValue(3u);
  ASSERT_TRUE(order_sub_3);
  ASSERT_EQ(
      BN_sub(order_sub_3.get(), ec_->GetOrderForTesting(), order_sub_3.get()),
      1);
  result = ec_->MultiplyWithGenerator(*order_sub_3, context_.get());
  EXPECT_TRUE(ec_->AreEqual(*inv_point3, *result, context_.get()));

  // Double point at infinity.
  crypto::ScopedEC_POINT point_at_inf = ec_->PointAtInfinityForTesting();
  result = ec_->Add(*point_at_inf, *point_at_inf, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->IsPointAtInfinity(*point_at_inf));
}

TEST_F(EllipticCurveTest, MultiplicationWithGenerator) {
  crypto::ScopedBIGNUM scalar1 = BigNumFromValue(123u);
  ASSERT_TRUE(scalar1);
  crypto::ScopedBIGNUM scalar2 = BigNumFromValue(321u);
  ASSERT_TRUE(scalar2);
  crypto::ScopedBIGNUM scalar_prod = CreateBigNum();
  ASSERT_TRUE(scalar_prod);
  ASSERT_EQ(
      BN_mul(scalar_prod.get(), scalar1.get(), scalar2.get(), context_.get()),
      1);
  EXPECT_EQ(BN_get_word(scalar_prod.get()), 123u * 321u);

  // Test if (G*scalar1)*scalar2 = G*(scalar1*scalar2).
  crypto::ScopedEC_POINT point1 =
      ec_->MultiplyWithGenerator(*scalar1, context_.get());
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point1, context_.get()));
  crypto::ScopedEC_POINT point2 =
      ec_->Multiply(*point1, *scalar2, context_.get());
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point2, context_.get()));
  crypto::ScopedEC_POINT point_prod =
      ec_->MultiplyWithGenerator(*scalar_prod, context_.get());
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point_prod, context_.get()));
  EXPECT_TRUE(ec_->AreEqual(*point2, *point_prod, context_.get()));
}

TEST_F(EllipticCurveTest, MultiplyWithGeneratorByBigScalars) {
  // Get big scalars of curve order.
  crypto::ScopedBIGNUM scalar1 = BigNumFromValue(123u);
  ASSERT_TRUE(scalar1);
  ASSERT_EQ(BN_sub(scalar1.get(), ec_->GetOrderForTesting(), scalar1.get()), 1);
  crypto::ScopedBIGNUM scalar2 = BigNumFromValue(321u);
  ASSERT_TRUE(scalar2);
  ASSERT_EQ(BN_sub(scalar2.get(), ec_->GetOrderForTesting(), scalar2.get()), 1);

  crypto::ScopedBIGNUM scalar_sum = CreateBigNum();
  ASSERT_TRUE(scalar_sum);
  ASSERT_EQ(BN_add(scalar_sum.get(), scalar1.get(), scalar2.get()), 1);
  // Expect scalar_sum > order.
  EXPECT_EQ(BN_cmp(scalar_sum.get(), ec_->GetOrderForTesting()), 1);
  // Multiplication by scalar greater than order should fail.
  EXPECT_FALSE(ec_->MultiplyWithGenerator(*scalar_sum, context_.get()));

  crypto::ScopedBIGNUM scalar_mod_sum =
      ec_->ModAdd(*scalar1, *scalar2, context_.get());
  ASSERT_TRUE(scalar_mod_sum);
  // Expect scalar_mod_sum < order.
  EXPECT_EQ(BN_cmp(scalar_mod_sum.get(), ec_->GetOrderForTesting()), -1);

  // Test if G*scalar1 + G*scalar2 = G*((scalar1 + scalar2) mod order).
  crypto::ScopedEC_POINT point1 =
      ec_->MultiplyWithGenerator(*scalar1, context_.get());
  ASSERT_TRUE(point1);
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point1, context_.get()));
  crypto::ScopedEC_POINT point2 =
      ec_->MultiplyWithGenerator(*scalar2, context_.get());
  ASSERT_TRUE(point2);
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point2, context_.get()));
  crypto::ScopedEC_POINT point_sum1 =
      ec_->MultiplyWithGenerator(*scalar_mod_sum, context_.get());
  ASSERT_TRUE(point_sum1);
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point_sum1, context_.get()));
  crypto::ScopedEC_POINT point_sum2 =
      ec_->Add(*point1, *point2, context_.get());
  ASSERT_TRUE(point_sum2);
  EXPECT_TRUE(ec_->IsPointValidAndFinite(*point_sum2, context_.get()));
  EXPECT_TRUE(ec_->AreEqual(*point_sum1, *point_sum2, context_.get()));
}

TEST_F(EllipticCurveTest, MultiplyWithGeneratorByZero) {
  crypto::ScopedBIGNUM scalar = BigNumFromValue(0);
  crypto::ScopedEC_POINT point =
      ec_->MultiplyWithGenerator(*scalar, context_.get());
  EXPECT_TRUE(ec_->IsPointValid(*point, context_.get()));
  EXPECT_TRUE(ec_->IsPointAtInfinity(*point));
}

TEST_F(EllipticCurveTest, MultiplyWithPointAtInfinity) {
  crypto::ScopedBIGNUM scalar = BigNumFromValue(123u);
  ASSERT_TRUE(scalar);
  crypto::ScopedEC_POINT point = ec_->PointAtInfinityForTesting();
  ASSERT_TRUE(point);

  crypto::ScopedEC_POINT result =
      ec_->Multiply(*point, *scalar, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->IsPointAtInfinity(*result));

  // Try 0 x point at infinity. The result should be also point at infinity.
  scalar = BigNumFromValue(0u);
  ASSERT_TRUE(scalar);
  result = ec_->Multiply(*point, *scalar, context_.get());
  ASSERT_TRUE(result);
  EXPECT_TRUE(ec_->IsPointAtInfinity(*result));
}

TEST_F(EllipticCurveTest, MultiplyWithInvalidPoint) {
  crypto::ScopedBIGNUM scalar = BigNumFromValue(1u);
  ASSERT_TRUE(scalar);
  crypto::ScopedEC_POINT point = CreateInvalidPoint();
  ASSERT_TRUE(point);

  // Verify that multiplication does not accept bogus point as the input.
  crypto::ScopedEC_POINT result =
      ec_->Multiply(*point, *scalar, context_.get());
  EXPECT_FALSE(result);
}

TEST_F(EllipticCurveTest, MultiplyWithGeneratorByNegative) {
  crypto::ScopedBIGNUM scalar1 = BigNumFromValue(123u);
  ASSERT_TRUE(scalar1);
  crypto::ScopedBIGNUM scalar2 = BigNumFromValue(321u);
  ASSERT_TRUE(scalar2);

  crypto::ScopedEC_POINT point1 =
      ec_->MultiplyWithGenerator(*scalar1, context_.get());
  crypto::ScopedEC_POINT point2 =
      ec_->MultiplyWithGenerator(*scalar2, context_.get());
  BN_set_negative(scalar1.get(), 1);
  crypto::ScopedEC_POINT inverse_point1 =
      ec_->MultiplyWithGenerator(*scalar1, context_.get());

  crypto::ScopedEC_POINT point_sum_12 =
      ec_->Add(*point1, *point2, context_.get());
  crypto::ScopedEC_POINT point_sum_all =
      ec_->Add(*point_sum_12, *inverse_point1, context_.get());
  // Validates that after adding the inversion of point1 its contribution
  // cancels out and we are left with point2.
  ASSERT_TRUE(ec_->AreEqual(*point2, *point_sum_all, context_.get()));
}

TEST_F(EllipticCurveTest, GenerateKey) {
  crypto::ScopedEC_KEY key = ec_->GenerateKey(context_.get());
  ASSERT_TRUE(key);
  const BIGNUM* private_key = EC_KEY_get0_private_key(key.get());
  ASSERT_TRUE(private_key);
  const EC_POINT* public_key = EC_KEY_get0_public_key(key.get());
  ASSERT_TRUE(public_key);

  // Validate that private_key * G = public_key.
  crypto::ScopedEC_POINT expected_public_key =
      ec_->MultiplyWithGenerator(*private_key, context_.get());
  EXPECT_TRUE(ec_->AreEqual(*expected_public_key, *public_key, context_.get()));
}

TEST_F(EllipticCurveTest, GenerateKeysAsSecureBlobs) {
  brillo::SecureBlob public_blob;
  brillo::SecureBlob private_blob;
  ASSERT_TRUE(ec_->GenerateKeysAsSecureBlobs(&public_blob, &private_blob,
                                             context_.get()));
  crypto::ScopedEC_POINT public_key =
      ec_->DecodeFromSpkiDer(public_blob, context_.get());
  ASSERT_TRUE(public_key);
  crypto::ScopedBIGNUM private_key = SecureBlobToBigNum(private_blob);
  ASSERT_TRUE(private_key);

  // Validate that private_key * G = public_key.
  crypto::ScopedEC_POINT expected_public_key =
      ec_->MultiplyWithGenerator(*private_key, context_.get());
  EXPECT_TRUE(ec_->AreEqual(*expected_public_key, *public_key, context_.get()));
}

TEST_F(EllipticCurveTest, InvertPoint) {
  crypto::ScopedBIGNUM scalar = BigNumFromValue(123u);
  ASSERT_TRUE(scalar);
  crypto::ScopedEC_POINT point =
      ec_->MultiplyWithGenerator(*scalar, context_.get());

  BN_set_negative(scalar.get(), 1);
  crypto::ScopedEC_POINT inverse_point =
      ec_->MultiplyWithGenerator(*scalar, context_.get());

  EXPECT_TRUE(ec_->InvertPoint(point.get(), context_.get()));

  // Validates that the inverted point equals to inverse_point.
  EXPECT_TRUE(ec_->AreEqual(*inverse_point, *point, context_.get()));
}

TEST_F(EllipticCurveTest, InversePointAddition) {
  crypto::ScopedBIGNUM scalar1 = BigNumFromValue(123u);
  ASSERT_TRUE(scalar1);
  crypto::ScopedBIGNUM scalar2 = BigNumFromValue(321u);
  ASSERT_TRUE(scalar2);

  crypto::ScopedEC_POINT point1 =
      ec_->MultiplyWithGenerator(*scalar1, context_.get());
  ASSERT_TRUE(point1);
  crypto::ScopedEC_POINT point2 =
      ec_->MultiplyWithGenerator(*scalar2, context_.get());
  ASSERT_TRUE(point2);
  crypto::ScopedEC_POINT point_sum_12 =
      ec_->Add(*point1, *point2, context_.get());
  ASSERT_TRUE(point_sum_12);

  ec_->InvertPoint(point1.get(), context_.get());
  crypto::ScopedEC_POINT point_sum_all =
      ec_->Add(*point_sum_12, *point1, context_.get());
  ASSERT_TRUE(point_sum_all);
  // Validates that after adding the inverted point1 its contribution
  // cancels out and we are left with point2.
  EXPECT_TRUE(ec_->AreEqual(*point2, *point_sum_all, context_.get()));
}

TEST_F(EllipticCurveTest, ScalarRangeCheck) {
  std::string str_ff(32, static_cast<char>(0xff));
  brillo::SecureBlob blob_ff(str_ff.begin(), str_ff.end());
  crypto::ScopedBIGNUM num_ff = SecureBlobToBigNum(blob_ff);
  EXPECT_FALSE(ec_->IsScalarValid(*num_ff));

  std::string str_23(32, static_cast<char>(0x23));
  brillo::SecureBlob blob_23(str_23.begin(), str_23.end());
  crypto::ScopedBIGNUM num_23 = SecureBlobToBigNum(blob_23);
  EXPECT_TRUE(ec_->IsScalarValid(*num_23));

  std::string str_cc(32, static_cast<char>(0xcc));
  brillo::SecureBlob blob_cc(str_cc.begin(), str_cc.end());
  crypto::ScopedBIGNUM num_cc = SecureBlobToBigNum(blob_cc);
  EXPECT_TRUE(ec_->IsScalarValid(*num_cc));

  std::string str_00(32, static_cast<char>(0));
  brillo::SecureBlob blob_00(str_00.begin(), str_00.end());
  crypto::ScopedBIGNUM num_00 = SecureBlobToBigNum(blob_00);
  EXPECT_TRUE(ec_->IsScalarValid(*num_00));

  EXPECT_FALSE(ec_->IsScalarValid(*ec_->GetOrderForTesting()));
}

}  // namespace hwsec_foundation
