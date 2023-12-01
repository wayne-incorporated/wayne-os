// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_U2F_H_
#define LIBHWSEC_FUZZED_U2F_H_

#include <memory>
#include <utility>

#include <base/containers/span.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/u2f.h"
#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/structures/u2f.h"

namespace hwsec {

class FakePublicKey : public u2f::PublicKey {
 public:
  FakePublicKey(brillo::Blob x, brillo::Blob y, brillo::Blob raw)
      : x_(std::move(x)), y_(std::move(y)), data_(std::move(raw)) {}

  base::span<const uint8_t> x() const override { return x_; }

  base::span<const uint8_t> y() const override { return y_; }

  const brillo::Blob& raw() const override { return data_; }

 private:
  brillo::Blob x_;
  brillo::Blob y_;
  brillo::Blob data_;
};

template <>
struct FuzzedObject<u2f::GenerateResult> {
  u2f::GenerateResult operator()(FuzzedDataProvider& provider) const {
    return u2f::GenerateResult{
        .public_key = std::make_unique<FakePublicKey>(
            brillo::BlobFromString(provider.ConsumeRandomLengthString()),
            brillo::BlobFromString(provider.ConsumeRandomLengthString()),
            brillo::BlobFromString(provider.ConsumeRandomLengthString())),
        .key_handle = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<u2f::Signature> {
  u2f::Signature operator()(FuzzedDataProvider& provider) const {
    return u2f::Signature{
        .r = FuzzedObject<brillo::Blob>()(provider),
        .s = FuzzedObject<brillo::Blob>()(provider),
    };
  }
};

template <>
struct FuzzedObject<u2f::Config> {
  u2f::Config operator()(FuzzedDataProvider& provider) const {
    return u2f::Config{
        .up_only_kh_size = FuzzedObject<size_t>()(provider),
        .kh_size = FuzzedObject<size_t>()(provider),
    };
  }
};
}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_U2F_H_
