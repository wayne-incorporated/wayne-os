// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>

#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

ScopedKey::ScopedKey(ScopedKey&& scoped_key)
    : key_(std::move(scoped_key.key_)),
      middleware_derivative_(std::move(scoped_key.middleware_derivative_)) {
  scoped_key.key_ = std::nullopt;
}

ScopedKey::~ScopedKey() {
  Invalidate();
}

void ScopedKey::Invalidate() {
  if (key_.has_value()) {
    Key key = GetKey();
    key_ = std::nullopt;

    // Using async flush if we have task runner on the current thread to improve
    // the performance.
    if (base::SequencedTaskRunner::HasCurrentDefault()) {
      base::OnceCallback<void(hwsec::Status)> callback =
          base::BindOnce([](hwsec::Status result) {
            if (!result.ok()) {
              LOG(ERROR) << "Failed to flush scoped key: " << result;
            }
          });
      Middleware(middleware_derivative_)
          .CallAsync<&hwsec::Backend::KeyManagement::Flush>(std::move(callback),
                                                            key);
    } else {
      RETURN_IF_ERROR(Middleware(middleware_derivative_)
                          .CallSync<&hwsec::Backend::KeyManagement::Flush>(key))
          .With([](auto linker) {
            return linker.LogError() << "Failed to flush scoped key";
          })
          .ReturnVoid();
    }
  }
}

ScopedKey& ScopedKey::operator=(ScopedKey&& scoped_key) {
  Invalidate();
  key_ = std::move(scoped_key.key_);
  middleware_derivative_ = std::move(scoped_key.middleware_derivative_);
  scoped_key.key_ = std::nullopt;
  return *this;
}

ScopedKey::ScopedKey(Key key, MiddlewareDerivative middleware_derivative)
    : key_(key), middleware_derivative_(std::move(middleware_derivative)) {}

const Key& ScopedKey::GetKey() const {
  return key_.value();
}

}  // namespace hwsec
