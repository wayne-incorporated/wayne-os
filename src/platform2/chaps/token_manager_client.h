// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_TOKEN_MANAGER_CLIENT_H_
#define CHAPS_TOKEN_MANAGER_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>

#include "chaps/threading_mode.h"
#include "chaps/token_manager_interface.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

class ChapsProxyImpl;

// TokenManagerClient is an implementation of TokenManagerInterface which sends
// the token management calls to the Chaps daemon. Example usage:
//   TokenManagerClient client;
//   client.OpenIsolate(&my_isolate_credential, &new_isolate_created);
//   client.LoadToken(my_isolate_credential,
//                    "path/to/token",
//                    "1234",
//                    "MyTokenLabel",
//                    &slot_id);
// Users of this class must instantiate AtExitManager, as the class relies on
// its presence.
//
// The default threading mode will create a standalone work thread, to prevent
// the extra thread, please use ThreadingMode::kCurrentThread.
class EXPORT_SPEC TokenManagerClient : public TokenManagerInterface {
 public:
  explicit TokenManagerClient(
      ThreadingMode mode = ThreadingMode::kStandaloneWorkerThread);
  TokenManagerClient(const TokenManagerClient&) = delete;
  TokenManagerClient& operator=(const TokenManagerClient&) = delete;

  virtual ~TokenManagerClient();

  // TokenManagerInterface methods.
  bool OpenIsolate(brillo::SecureBlob* isolate_credential,
                   bool* new_isolate_created) override;
  void CloseIsolate(const brillo::SecureBlob& isolate_credential) override;
  bool LoadToken(const brillo::SecureBlob& isolate_credential,
                 const base::FilePath& path,
                 const brillo::SecureBlob& auth_data,
                 const std::string& label,
                 int* slot_id) override;
  bool UnloadToken(const brillo::SecureBlob& isolate_credential,
                   const base::FilePath& path) override;
  bool GetTokenPath(const brillo::SecureBlob& isolate_credential,
                    int slot_id,
                    base::FilePath* path) override;

  // Convenience method, not on TokenManagerInterface.
  // Returns true on success, false on failure. If it succeeds, stores a list of
  // the paths of all loaded tokens in |results|.
  virtual bool GetTokenList(const brillo::SecureBlob& isolate_credential,
                            std::vector<std::string>* results);

 private:
  ThreadingMode mode_;
  std::unique_ptr<ChapsProxyImpl> proxy_;

  // Attempts to connect to the Chaps daemon. Returns true on success.
  bool Connect();
};

}  // namespace chaps

#endif  // CHAPS_TOKEN_MANAGER_CLIENT_H_
