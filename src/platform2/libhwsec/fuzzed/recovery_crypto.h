// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_RECOVERY_CRYPTO_H_
#define LIBHWSEC_FUZZED_RECOVERY_CRYPTO_H_

#include <optional>
#include <string>
#include <type_traits>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>

#include "libhwsec/backend/recovery_crypto.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<EncryptEccPrivateKeyResponse> {
  EncryptEccPrivateKeyResponse operator()(FuzzedDataProvider& provider) const {
    return EncryptEccPrivateKeyResponse{
        .encrypted_own_priv_key = FuzzedObject<brillo::Blob>()(provider),
        .extended_pcr_bound_own_priv_key =
            FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<RecoveryCryptoRsaKeyPair> {
  RecoveryCryptoRsaKeyPair operator()(FuzzedDataProvider& provider) const {
    return RecoveryCryptoRsaKeyPair{
        .encrypted_rsa_private_key = FuzzedObject<brillo::Blob>()(provider),
        .rsa_public_key_spki_der = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<BN_CTX&> {
  BN_CTX& operator()(FuzzedDataProvider& provider) const {
    using hwsec_foundation::CreateBigNumContext;
    using hwsec_foundation::ScopedBN_CTX;
    static ScopedBN_CTX context = CreateBigNumContext();
    CHECK(context.get());
    return *context;
  }
};

template <>
struct FuzzedObject<BN_CTX*> {
  BN_CTX* operator()(FuzzedDataProvider& provider) const {
    if (provider.ConsumeBool()) {
      return nullptr;
    }
    return &FuzzedObject<BN_CTX&>()(provider);
  }
};

template <>
struct FuzzedObject<const hwsec_foundation::EllipticCurve&> {
  const hwsec_foundation::EllipticCurve& operator()(
      FuzzedDataProvider& provider) const {
    enum class FuzzCurve {
      k256,
      k384,
      k521,
      kMaxValue = k521,
    };

    using hwsec_foundation::EllipticCurve;

    static std::optional<EllipticCurve> ec_256 =
        EllipticCurve::Create(EllipticCurve::CurveType::kPrime256,
                              &FuzzedObject<BN_CTX&>()(provider));
    static std::optional<EllipticCurve> ec_384 =
        EllipticCurve::Create(EllipticCurve::CurveType::kPrime384,
                              &FuzzedObject<BN_CTX&>()(provider));
    static std::optional<EllipticCurve> ec_521 =
        EllipticCurve::Create(EllipticCurve::CurveType::kPrime521,
                              &FuzzedObject<BN_CTX&>()(provider));

    switch (provider.ConsumeEnum<FuzzCurve>()) {
      case FuzzCurve::k256:
        CHECK(ec_256.has_value());
        return *ec_256;
      case FuzzCurve::k384:
        CHECK(ec_384.has_value());
        return *ec_384;
      case FuzzCurve::k521:
        CHECK(ec_521.has_value());
        return *ec_521;
    }
  }
};

template <>
struct FuzzedObject<crypto::ScopedEC_KEY> {
  crypto::ScopedEC_KEY operator()(FuzzedDataProvider& provider) const {
    if (provider.ConsumeBool()) {
      return nullptr;
    }

    const hwsec_foundation::EllipticCurve& ec =
        FuzzedObject<const hwsec_foundation::EllipticCurve&>()(provider);
    return ec.GenerateKey(FuzzedObject<BN_CTX*>()(provider));
  }
};

template <>
struct FuzzedObject<EncryptEccPrivateKeyRequest> {
  EncryptEccPrivateKeyRequest operator()(FuzzedDataProvider& provider) const {
    return EncryptEccPrivateKeyRequest{
        .ec = FuzzedObject<const hwsec_foundation::EllipticCurve&>()(provider),
        .own_key_pair = FuzzedObject<crypto::ScopedEC_KEY>()(provider),
        .auth_value =
            FuzzedObject<std::optional<brillo::SecureBlob>>()(provider),
        .current_user = FuzzedObject<std::string>()(provider),
    };
  }
};

template <>
struct FuzzedObject<GenerateDhSharedSecretRequest> {
  GenerateDhSharedSecretRequest operator()(FuzzedDataProvider& provider) const {
    return GenerateDhSharedSecretRequest{
        .ec = FuzzedObject<const hwsec_foundation::EllipticCurve&>()(provider),
        .encrypted_own_priv_key = FuzzedObject<brillo::Blob>()(provider),
        .extended_pcr_bound_own_priv_key =
            FuzzedObject<brillo::Blob>()(provider),
        .auth_value =
            FuzzedObject<std::optional<brillo::SecureBlob>>()(provider),
        .current_user = FuzzedObject<std::string>()(provider),
        .others_pub_point = FuzzedObject<crypto::ScopedEC_POINT>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_RECOVERY_CRYPTO_H_
