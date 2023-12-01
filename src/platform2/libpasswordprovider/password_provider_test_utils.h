// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_TEST_UTILS_H_
#define LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_TEST_UTILS_H_

#include <memory>
#include <string>

#include "libpasswordprovider/password.h"

namespace password_provider {
namespace test {

// Util functions for testing with libpasswordprovider.
//
// TODO(maybelle): Export this into libpasswordprovider-test
std::unique_ptr<Password> CreatePassword(const char* data, size_t len) {
  auto password = std::make_unique<Password>();
  if (!password->Init()) {
    return nullptr;
  }

  if (len > password->max_size()) {
    return nullptr;
  }

  memcpy(password->GetMutableRaw(), data, len);
  memset(password->GetMutableRaw() + len, '\0', 1);
  password->SetSize(len);

  return password;
}

static std::unique_ptr<Password> CreatePassword(const std::string& data) {
  return CreatePassword(data.c_str(), data.size());
}

}  // namespace test
}  // namespace password_provider

#endif  // LIBPASSWORDPROVIDER_PASSWORD_PROVIDER_TEST_UTILS_H_
