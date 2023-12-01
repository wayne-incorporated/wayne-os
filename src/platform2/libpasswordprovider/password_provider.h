// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_H_
#define LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_H_

#include <memory>

#include <brillo/brillo_export.h>

#include "libpasswordprovider/libpasswordprovider_export.h"
#include "libpasswordprovider/password.h"

namespace password_provider {

class LIBPASSWORDPROVIDER_EXPORT PasswordProviderInterface {
 public:
  virtual ~PasswordProviderInterface() {}

  // Saves the given password to the keyring of the calling process.
  // The password will be available to be retrieved until the process that calls
  // SavePassword dies.
  virtual bool SavePassword(const Password& password) const = 0;

  // Retrieves the given password. The returned password will be null
  // terminated. Calling GetPassword after DiscardPassword has been called by
  // any process will return false.
  virtual std::unique_ptr<Password> GetPassword() const = 0;

  // Discards the saved password.
  virtual bool DiscardPassword() const = 0;
};

// Implementation of password storage. This is a wrapper around Linux keyring
// functions.
class LIBPASSWORDPROVIDER_EXPORT PasswordProvider
    : public PasswordProviderInterface {
 public:
  PasswordProvider();
  PasswordProvider(const PasswordProvider&) = delete;
  PasswordProvider& operator=(const PasswordProvider&) = delete;

  // PasswordProviderInterface overrides
  bool SavePassword(const Password& password) const override;
  std::unique_ptr<Password> GetPassword() const override;
  bool DiscardPassword() const override;
};

}  // namespace password_provider

#endif  // LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_H_
