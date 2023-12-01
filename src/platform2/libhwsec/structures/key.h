// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_KEY_H_
#define LIBHWSEC_STRUCTURES_KEY_H_

#include <optional>

#include "libhwsec/hwsec_export.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

using KeyToken = uint32_t;

enum class KeyAlgoType {
  kRsa,
  kEcc,
};

struct Key {
  NoDefault<KeyToken> token;
};

class HWSEC_EXPORT ScopedKey {
 public:
  ScopedKey(ScopedKey&& scoped_key);
  ScopedKey(const ScopedKey& scoped_key) = delete;
  ScopedKey(Key key, MiddlewareDerivative middleware_derivative);
  ~ScopedKey();

  ScopedKey& operator=(ScopedKey&& scoped_key);
  ScopedKey& operator=(const ScopedKey& scoped_key) = delete;

  const Key& GetKey() const;

 private:
  void Invalidate();

  std::optional<Key> key_;
  MiddlewareDerivative middleware_derivative_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_KEY_H_
