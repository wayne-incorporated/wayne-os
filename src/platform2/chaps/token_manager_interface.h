// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_TOKEN_MANAGER_INTERFACE_H_
#define CHAPS_TOKEN_MANAGER_INTERFACE_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>

namespace chaps {

// TokenManagerInterface is an interface for Chaps-specific token management
// operations which are not part of the PKCS #11 interface.
//
//   Some operations are parameterized with a path to the associated persistent
//   token files. This path is unique per token and a token is unique per path.
//   This 1-to-1 relation can be assumed.
//
//   Authorization data associated with a token is typically derived from the
//   user's password and is provided when a token is loaded or when the password
//   is changed.
class TokenManagerInterface {
 public:
  // Open an isolate into which tokens can be loaded. To attempt to open an
  // existing isolate, pass its isolate credential, otherwise pass be empty
  // SecureBlob to create a new isolate.  Returns true if successful.
  //
  //  isolate_credential - The users isolate into which to login, or a empty if
  //                 logging in to a new isolate. On return contains the isolate
  //                 credential for the isolate the user is logged in on.
  //  new_isolate_created - Returns true if a new isolate was created (in which
  //                        case isolate_credential will be set to the new
  //                        isolate's credential), or false if the call
  //                        succeeded in opening the existing isolate.
  virtual bool OpenIsolate(brillo::SecureBlob* isolate_credential,
                           bool* new_isolate_created) = 0;

  // Close a given isolate. If all outstanding OpenIsolate calls have been
  // closed, then all tokens will be unloaded from the isolate and the isolate
  // will be destroyed.
  //
  //  isolate_credential - The isolate into which they are logging out from.
  virtual void CloseIsolate(const brillo::SecureBlob& isolate_credential) = 0;

  // Loads a token into the given isolate.  Returns true on success.
  //
  //  isolate_credential - The isolate into which the token should be loaded.
  //  path - The path to the token directory.
  //  auth_data - Authorization data to unlock the token.
  //  slot_id - On success, will be set to the loaded token's slot ID.
  virtual bool LoadToken(const brillo::SecureBlob& isolate_credential,
                         const base::FilePath& path,
                         const brillo::SecureBlob& auth_data,
                         const std::string& label,
                         int* slot_id) = 0;

  // Unloads a token from the given isolate. Returns true on success.
  //
  //  isolate_credential - The isolate from which the token should be unloaded.
  //  path - The path to the token directory.
  virtual bool UnloadToken(const brillo::SecureBlob& isolate_credential,
                           const base::FilePath& path) = 0;

  // Provides the token path associated with the given slot.  Returns true on
  // success.  Returns false if the slot does not exist in the given isolate or
  // if no token is loaded in the given slot.
  //
  // isolate_credentials - The isolate associated with the slot.
  // slot_id - Identifies the slot.
  // path - On success, will be set to the token path for the slot.
  virtual bool GetTokenPath(const brillo::SecureBlob& isolate_credential,
                            int slot_id,
                            base::FilePath* path) = 0;
};

}  // namespace chaps

#endif  // CHAPS_TOKEN_MANAGER_INTERFACE_H_
