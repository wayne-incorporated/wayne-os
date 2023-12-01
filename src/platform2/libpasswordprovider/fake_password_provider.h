// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBPASSWORDPROVIDER_FAKE_PASSWORD_PROVIDER_H_
#define LIBPASSWORDPROVIDER_FAKE_PASSWORD_PROVIDER_H_

#include "libpasswordprovider/password_provider.h"

#include <memory>
#include <string>

#include "libpasswordprovider/password.h"

namespace password_provider {

// Fake implementation of password storage.
//
// TODO(maybelle): Export this into libpasswordprovider-test
class FakePasswordProvider : public PasswordProviderInterface {
 public:
  FakePasswordProvider() {}
  FakePasswordProvider(const FakePasswordProvider&) = delete;
  FakePasswordProvider& operator=(const FakePasswordProvider&) = delete;

  bool password_saved() const { return password_saved_; }
  bool password_discarded() const {
    return password_discarded_ && password_.size() == 0;
  }

  // PasswordProviderInterface overrides
  bool SavePassword(const Password& password) const override {
    password_saved_ = true;

    password_ = std::string(password.GetRaw(), password.size());
    return true;
  }

  std::unique_ptr<Password> GetPassword() const override {
    if (password_discarded()) {
      return nullptr;
    }

    auto password = std::make_unique<Password>();
    if (!password->Init()) {
      return nullptr;
    }

    memcpy(password->GetMutableRaw(), password_.c_str(), password_.size());
    password->SetSize(password_.size());

    return password;
  }

  bool DiscardPassword() const override {
    password_.clear();
    password_discarded_ = true;
    return true;
  }

 private:
  mutable bool password_saved_ = false;  // true if the password was ever saved.
  mutable bool password_discarded_ =
      false;  // true if password_ is cleared out.
  mutable std::string password_;
};

}  // namespace password_provider

#endif  // LIBPASSWORDPROVIDER_FAKE_PASSWORD_PROVIDER_H_
