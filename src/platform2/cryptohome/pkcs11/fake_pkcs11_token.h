// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PKCS11_FAKE_PKCS11_TOKEN_H_
#define CRYPTOHOME_PKCS11_FAKE_PKCS11_TOKEN_H_

#include "cryptohome/pkcs11/pkcs11_token.h"

namespace cryptohome {

class FakePkcs11Token final : public Pkcs11Token {
 public:
  FakePkcs11Token() : ready_(false) {}

  ~FakePkcs11Token() override = default;

  bool Insert() override {
    ready_ = true;
    return true;
  }

  void Remove() override { ready_ = false; }

  bool IsReady() const override { return ready_; }

 private:
  bool ready_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_FAKE_PKCS11_TOKEN_H_
