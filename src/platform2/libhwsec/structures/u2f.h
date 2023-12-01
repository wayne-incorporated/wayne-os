// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_U2F_H_
#define LIBHWSEC_STRUCTURES_U2F_H_

#include <memory>

#include <base/containers/span.h>
#include <brillo/secure_blob.h>

#include "libhwsec/hwsec_export.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {
namespace u2f {

class PublicKey {
 public:
  virtual ~PublicKey() = default;

  virtual base::span<const uint8_t> x() const = 0;
  virtual base::span<const uint8_t> y() const = 0;
  virtual const brillo::Blob& raw() const = 0;
};

struct GenerateResult {
  std::unique_ptr<PublicKey> public_key;
  NoDefault<brillo::Blob> key_handle;
};

struct Signature {
  NoDefault<brillo::Blob> r;
  NoDefault<brillo::Blob> s;
};

enum class ConsumeMode : bool {
  kNoConsume,
  kConsume,
};

enum class UserPresenceMode : bool {
  kNotRequired,
  kRequired,
};

struct Config {
  size_t up_only_kh_size;
  size_t kh_size;
};

}  // namespace u2f
}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_U2F_H_
