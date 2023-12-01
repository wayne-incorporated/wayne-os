// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_BASIC_OBJECTS_H_
#define LIBHWSEC_FUZZED_BASIC_OBJECTS_H_

#include <map>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <base/notreached.h>
#include <base/time/time.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/sha.h>

// This file contains the fuzzed generator for basic objects.
// The basic type means primitive type or everything that is belong to "std",
// "absl", "base", "brillo" namespaces.

namespace hwsec {

// FuzzedObject would generate a fuzzed data from the input type.
//
// Template parameters:
//   |FuzzedType| - The type of the data to be generate.
//   |Enable| - The enable_if_t helper field.
template <typename FuzzedType, typename Enable = void>
struct FuzzedObject {
  // You have to have a specialization for FuzzedObject.
  FuzzedObject() = delete;
};

// Generates fuzzed enum.
// If the enum has kMaxValue, the generate value will not exceed it.
template <typename T>
struct FuzzedObject<T, std::enable_if_t<std::is_enum_v<T>>> {
  // A helper to check an enum has kMaxValue or not.
  template <typename E, typename Enable = void>
  struct EnumHasMaxValue {
    static constexpr inline bool value = false;
  };

  template <typename E>
  struct EnumHasMaxValue<E, std::void_t<decltype(E::kMaxValue)>> {
    static constexpr inline bool value = true;
  };

  T operator()(FuzzedDataProvider& provider) const {
    if constexpr (EnumHasMaxValue<T>::value) {
      return provider.ConsumeEnum<T>();
    } else {
      return static_cast<T>(
          provider.ConsumeIntegral<std::underlying_type_t<T>>());
    }
  }
};

// Generates fuzzed integral.
template <typename T>
struct FuzzedObject<
    T,
    std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<bool, T>>> {
  T operator()(FuzzedDataProvider& provider) const {
    return provider.ConsumeIntegral<T>();
  }
};

// Generates fuzzed bool.
template <>
struct FuzzedObject<bool> {
  bool operator()(FuzzedDataProvider& provider) const {
    return provider.ConsumeBool();
  }
};

// Generates fuzzed brillo::SecureBlob.
template <>
struct FuzzedObject<brillo::SecureBlob> {
  brillo::SecureBlob operator()(FuzzedDataProvider& provider) const {
    return brillo::SecureBlob(provider.ConsumeRandomLengthString());
  }
};

// Generates fuzzed brillo::Blob.
template <>
struct FuzzedObject<brillo::Blob> {
  brillo::Blob operator()(FuzzedDataProvider& provider) const {
    return brillo::BlobFromString(provider.ConsumeRandomLengthString());
  }
};

// Generates fuzzed std::string.
template <>
struct FuzzedObject<std::string> {
  std::string operator()(FuzzedDataProvider& provider) const {
    return provider.ConsumeRandomLengthString();
  }
};

// Generates fuzzed std::set.
template <typename T>
struct FuzzedObject<std::set<T>> {
  std::set<T> operator()(FuzzedDataProvider& provider) const {
    std::set<T> result;
    for (auto& data : FuzzedObject<std::vector<T>>()(provider)) {
      result.insert(std::move(data));
    }
    return result;
  }
};

// Generates fuzzed std::map.
template <typename T, typename U>
struct FuzzedObject<std::map<T, U>> {
  std::map<T, U> operator()(FuzzedDataProvider& provider) const {
    std::map<T, U> result;
    while (provider.ConsumeBool()) {
      result.insert({FuzzedObject<T>()(provider), FuzzedObject<U>()(provider)});
    }
    return result;
  }
};

// Generates fuzzed absl::flat_hash_set.
template <typename T>
struct FuzzedObject<absl::flat_hash_set<T>> {
  absl::flat_hash_set<T> operator()(FuzzedDataProvider& provider) const {
    absl::flat_hash_set<T> result;
    for (auto& data : FuzzedObject<std::vector<T>>()(provider)) {
      result.insert(std::move(data));
    }
    return result;
  }
};

// Generates fuzzed absl::flat_hash_map.
template <typename T, typename U>
struct FuzzedObject<absl::flat_hash_map<T, U>> {
  absl::flat_hash_map<T, U> operator()(FuzzedDataProvider& provider) const {
    absl::flat_hash_map<T, U> result;
    for (auto& [key, value] : FuzzedObject<std::map<T, U>>()(provider)) {
      result.insert({key, std::move(value)});
    }
    return result;
  }
};

// Generates fuzzed std::vector.
// Excludes the uint8_t variant, because it's covered by brillo::Blob.
template <typename T>
struct FuzzedObject<std::vector<T>,
                    std::enable_if_t<!std::is_same_v<T, uint8_t>>> {
  std::vector<T> operator()(FuzzedDataProvider& provider) const {
    std::vector<T> result;
    while (provider.ConsumeBool()) {
      result.push_back(FuzzedObject<T>()(provider));
    }
    return result;
  }
};

// Generates fuzzed std::optional.
template <typename T>
struct FuzzedObject<std::optional<T>> {
  std::optional<T> operator()(FuzzedDataProvider& provider) const {
    if (!provider.ConsumeBool()) {
      return std::nullopt;
    }
    return FuzzedObject<T>()(provider);
  }
};

// Generates fuzzed std::monostate.
template <>
struct FuzzedObject<std::monostate> {
  std::monostate operator()(FuzzedDataProvider& provider) const {
    return std::monostate();
  }
};

// Generates fuzzed std::variant.
template <typename... VariantArgs>
struct FuzzedObject<std::variant<VariantArgs...>> {
  using Variant = std::variant<VariantArgs...>;

  Variant operator()(FuzzedDataProvider& provider) const {
    size_t idx =
        provider.ConsumeIntegralInRange<size_t>(0, sizeof...(VariantArgs) - 1);
    return (*this)(provider, idx, std::index_sequence_for<VariantArgs...>{});
  }

  Variant operator()(FuzzedDataProvider& provider,
                     size_t idx,
                     std::index_sequence<> int_seq) const {
    NOTREACHED() << "Should not reach here.";
    // We should not reach here.
    return FuzzedObject<Variant>()(provider);
  }

  template <size_t Index, size_t... RemainingIndexes>
  Variant operator()(
      FuzzedDataProvider& provider,
      size_t idx,
      std::index_sequence<Index, RemainingIndexes...> int_seq) const {
    if (idx == Index) {
      return FuzzedObject<std::variant_alternative_t<Index, Variant>>()(
          provider);
    }
    return (*this)(provider, idx, std::index_sequence<RemainingIndexes...>{});
  }
};

template <>
struct FuzzedObject<crypto::ScopedEC_POINT> {
  crypto::ScopedEC_POINT operator()(FuzzedDataProvider& provider) const {
    if (provider.ConsumeBool()) {
      return nullptr;
    }

    hwsec_foundation::ScopedBN_CTX context =
        hwsec_foundation::CreateBigNumContext();

    std::optional<hwsec_foundation::EllipticCurve> ec_256 =
        hwsec_foundation::EllipticCurve::Create(
            hwsec_foundation::EllipticCurve::CurveType::kPrime256,
            context.get());

    CHECK(ec_256.has_value());

    crypto::ScopedBIGNUM private_key = hwsec_foundation::SecureBlobToBigNum(
        hwsec_foundation::Sha256(FuzzedObject<brillo::SecureBlob>()(provider)));

    return ec_256->MultiplyWithGenerator(*private_key, context.get());
  }
};

template <>
struct FuzzedObject<base::TimeDelta> {
  base::TimeDelta operator()(FuzzedDataProvider& provider) const {
    return base::Microseconds(provider.ConsumeIntegral<int64_t>());
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_BASIC_OBJECTS_H_
