// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_PKCS11_UTIL_H_
#define SHILL_STORE_PKCS11_UTIL_H_

#include <string>

#include <chaps/pkcs11/cryptoki.h>

namespace shill::pkcs11 {

constexpr CK_SLOT_ID kInvalidSlot = ULONG_MAX;

// A helper class to scope a PKCS #11 session.
class ScopedSession {
 public:
  explicit ScopedSession(CK_SLOT_ID slot);
  ScopedSession(const ScopedSession&) = delete;
  ScopedSession& operator=(const ScopedSession&) = delete;
  ~ScopedSession();

  CK_SESSION_HANDLE handle() const { return handle_; }

  bool IsValid() const { return (handle_ != CK_INVALID_HANDLE); }

 private:
  CK_SESSION_HANDLE handle_ = CK_INVALID_HANDLE;
};

// The Slot enum indicates the type of PKCS#11 slot used.
enum Slot : int {
  kUnknown,
  kSystem,  // Slot associated to the device
  kUser,    // Slot associated to a certain user
};

struct Pkcs11Id {
  CK_SLOT_ID slot_id;
  std::string cka_id;

  // Parses a Pkcs11Id from a colon-separated "slot_id:cka_id" representation.
  static std::optional<Pkcs11Id> ParseFromColonSeparated(
      const std::string& pkcs11_id);

  // Emits a colon-separated "slot_id:cka_id" representation.
  std::string ToColonSeparated();
};

}  // namespace shill::pkcs11

#endif  // SHILL_STORE_PKCS11_UTIL_H_
