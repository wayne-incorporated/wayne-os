// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PKCS11_PKCS11_TOKEN_H_
#define CRYPTOHOME_PKCS11_PKCS11_TOKEN_H_

namespace cryptohome {

class Pkcs11Token {
 public:
  virtual ~Pkcs11Token() = default;

  virtual bool Insert() = 0;
  virtual void Remove() = 0;
  virtual bool IsReady() const = 0;
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_PKCS11_TOKEN_H_
