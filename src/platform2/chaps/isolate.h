// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_ISOLATE_H_
#define CHAPS_ISOLATE_H_

#include <string>

#include <brillo/secure_blob.h>

#include "chaps/chaps.h"

namespace chaps {

inline constexpr size_t kIsolateCredentialBytes = 16;

// Manages a user's isolate credentials, including saving and retrieval of
// isolate credentials. Sample usage:
//   IsolateCredentialManager isolate_manager;
//   SecureBlob isolate_credential;
//   isolate_manager.GetCurrentUserIsolateCredential(&isolate_credential);
//
// Only virtual to enable mocking in tests.
class IsolateCredentialManager {
 public:
  IsolateCredentialManager();
  IsolateCredentialManager(const IsolateCredentialManager&) = delete;
  IsolateCredentialManager& operator=(const IsolateCredentialManager&) = delete;

  virtual ~IsolateCredentialManager();

  // Get the well known credential for the default isolate.
  static brillo::SecureBlob GetDefaultIsolateCredential() {
    // Default isolate credential is all zeros.
    return brillo::SecureBlob(kIsolateCredentialBytes);
  }

  // Get the isolate credential for the current user, returning true if it
  // exists.
  virtual bool GetCurrentUserIsolateCredential(
      brillo::SecureBlob* isolate_credential);

  // Get the isolate credential for the given user name, returning true if it
  // exists.
  virtual bool GetUserIsolateCredential(const std::string& user,
                                        brillo::SecureBlob* isolate_credential);

  // Save the isolate credential such that it can be retrieved with
  // GetUserIsolateCredential. Return true on success and false on failure.
  virtual bool SaveIsolateCredential(
      const std::string& user, const brillo::SecureBlob& isolate_credential);
};

}  // namespace chaps

#endif  // CHAPS_ISOLATE_H_
