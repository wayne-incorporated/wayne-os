// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_DBUS_RESULT_H_
#define HERMES_DBUS_RESULT_H_

#include <memory>
#include <utility>

namespace hermes {

template <typename... T>
class DbusResult {
 public:
  using DBusResponse = brillo::dbus_utils::DBusMethodResponse<T...>;
  explicit DbusResult(std::unique_ptr<DBusResponse> response)
      : response_(std::move(response)) {}
  DbusResult(const DbusResult&) = default;
  DbusResult(DbusResult&&) = default;
  DbusResult& operator=(const DbusResult&) = default;
  DbusResult& operator=(DbusResult&&) = default;

  void Success(const T&... object) const { response_->Return(object...); }
  void Error(const brillo::ErrorPtr& decoded_error) const {
    response_->ReplyWithError(decoded_error.get());
  }

 private:
  std::shared_ptr<DBusResponse> response_;
};

}  // namespace hermes

#endif  // HERMES_DBUS_RESULT_H_
