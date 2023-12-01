// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_DBUS_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_DBUS_UTILS_H_

#include <utility>

#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <brillo/errors/error.h>

namespace diagnostics {

// SplitDbusCallback turns a callback into two callbacks, one for results,
// another for error. This is for who want to use one callback to handle the
// result from dbus binding.
// It turns |void(err, result...)| into |void(result...)| and |void(err)|.
template <typename... Args>
auto SplitDbusCallback(
    base::OnceCallback<void(brillo::Error*, Args...)>&& callback) {
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  auto on_success = base::BindOnce(
      [](base::OnceCallback<void(brillo::Error*, Args...)>&& callback,
         Args... args) { std::move(callback).Run(nullptr, args...); },
      std::move(cb1));
  auto on_error = base::BindOnce(
      [](base::OnceCallback<void(brillo::Error*, Args...)>&& callback,
         brillo::Error* err) { std::move(callback).Run(err, Args{}...); },
      std::move(cb2));
  return std::make_pair(std::move(on_success), std::move(on_error));
}

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_DBUS_UTILS_H_
