// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This provides some utility functions to do with chaps isolate support.

#include "chaps/isolate.h"

#include <string>

#include <brillo/secure_blob.h>

using brillo::SecureBlob;
using std::string;

namespace chaps {

IsolateCredentialManager::IsolateCredentialManager() {}

IsolateCredentialManager::~IsolateCredentialManager() {}

bool IsolateCredentialManager::GetCurrentUserIsolateCredential(
    SecureBlob* isolate_credential) {
  // On Chrome OS always use the default isolate credential.
  *isolate_credential = GetDefaultIsolateCredential();
  return true;
}

bool IsolateCredentialManager::GetUserIsolateCredential(
    const string& user, SecureBlob* isolate_credential) {
  // On Chrome OS always use the default isolate credential.
  *isolate_credential = GetDefaultIsolateCredential();
  return true;
}

bool IsolateCredentialManager::SaveIsolateCredential(
    const string& user, const SecureBlob& isolate_credential) {
  // On Chrome OS we don't save isolate credentials.
  return false;
}

}  // namespace chaps
