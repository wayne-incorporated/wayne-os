// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_DBUS_TEST_UTIL_H_
#define LOGIN_MANAGER_DBUS_TEST_UTIL_H_

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/memory/weak_ptr.h>
#include <brillo/cryptohome.h>

namespace login_manager {

// A gtest matcher to match dbus::MethodCall by interface and method name.
MATCHER_P(DBusMethodCallEq, other, "Equality matcher for dbus::MethodCall") {
  return arg->GetInterface() == other->GetInterface() &&
         arg->GetMember() == other->GetMember();
}

// Captures the D-Bus Response object passed via DBusMethodResponse via
// ResponseSender.
//
// Example Usage:
//   ResponseCapturer capture;
//   impl_->SomeAsyncDBusMethod(capturer.CreateMethodResponse(), ...);
//   EXPECT_EQ(SomeErrorName, capture.response()->GetErrorName());
class ResponseCapturer {
 public:
  ResponseCapturer()
      : call_("org.chromium.SessionManagerInterface", "PlaceholderDbusMethod"),
        weak_ptr_factory_(this) {
    call_.SetSerial(1);  // Placeholder serial is needed.
  }
  ResponseCapturer(const ResponseCapturer&) = delete;
  ResponseCapturer& operator=(const ResponseCapturer&) = delete;

  ~ResponseCapturer() = default;

  // Needs to be non-const, because some accessors like GetErrorName() are
  // non-const.
  dbus::Response* response() { return response_.get(); }

  template <typename... Types>
  std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<Types...>>
  CreateMethodResponse() {
    return std::make_unique<brillo::dbus_utils::DBusMethodResponse<Types...>>(
        &call_,
        base::Bind(&ResponseCapturer::Capture, weak_ptr_factory_.GetWeakPtr()));
  }

 private:
  void Capture(std::unique_ptr<dbus::Response> response) {
    DCHECK(!response_);
    response_ = std::move(response);
  }

  dbus::MethodCall call_;
  std::unique_ptr<dbus::Response> response_;
  base::WeakPtrFactory<ResponseCapturer> weak_ptr_factory_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_DBUS_TEST_UTIL_H_
