// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_util.h"

#include <memory>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <chaps/pkcs11/cryptoki.h>

namespace shill::pkcs11 {

ScopedSession::ScopedSession(CK_SLOT_ID slot) {
  CK_C_INITIALIZE_ARGS args{
      .flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS,
  };
  CK_RV rv = C_Initialize(&args);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    // This may be normal in a test environment.
    LOG(INFO) << "PKCS #11 is not available. C_Initialize rv: " << rv;
    return;
  }
  CK_FLAGS flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
  rv = C_OpenSession(slot, flags, nullptr, nullptr, &handle_);
  if (rv != CKR_OK) {
    LOG(ERROR) << "Failed to open PKCS #11 session. C_OpenSession rv: " << rv;
  }
}

ScopedSession::~ScopedSession() {
  if (IsValid() && (C_CloseSession(handle_) != CKR_OK)) {
    LOG(WARNING) << "Failed to close PKCS #11 session.";
  }
  handle_ = CK_INVALID_HANDLE;
}

std::optional<Pkcs11Id> Pkcs11Id::ParseFromColonSeparated(
    const std::string& pkcs11_id) {
  const std::vector<std::string> data = base::SplitString(
      pkcs11_id, ":", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_NONEMPTY);
  if (data.size() != 2) {
    LOG(ERROR) << "Invalid PKCS#11 ID " << pkcs11_id;
    return {};
  }
  uint32_t slot_id;
  if (!base::StringToUint(data[0], &slot_id)) {
    LOG(ERROR) << "Invalid slot ID " << data[0];
    return {};
  }
  return std::optional<Pkcs11Id>({slot_id, data[1]});
}

std::string Pkcs11Id::ToColonSeparated() {
  return base::StringPrintf("%lu:%s", slot_id, cka_id.c_str());
}

}  // namespace shill::pkcs11
