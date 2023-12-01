// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/pkcs11/real_pkcs11_token.h"

#include <memory>
#include <string>
#include <utility>

#include <brillo/secure_blob.h>

#include <chaps/isolate.h>
#include <chaps/token_manager_client.h>
#include "cryptohome/chaps_client_factory.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/pkcs11_init.h"

namespace cryptohome {

using chaps::IsolateCredentialManager;

RealPkcs11Token::RealPkcs11Token(
    const Username& username,
    const base::FilePath& token_dir,
    const brillo::SecureBlob& auth_data,
    std::unique_ptr<ChapsClientFactory> chaps_client_factory)
    : username_(username),
      token_dir_(token_dir),
      auth_data_(auth_data),
      chaps_client_factory_(std::move(chaps_client_factory)),
      ready_(false) {}

RealPkcs11Token::~RealPkcs11Token() {
  Remove();
}

bool RealPkcs11Token::Insert() {
  std::unique_ptr<chaps::TokenManagerClient> chaps_client(
      chaps_client_factory_->New());

  Pkcs11Init pkcs11init;
  int slot_id = 0;
  if (!chaps_client->LoadToken(
          IsolateCredentialManager::GetDefaultIsolateCredential(), token_dir_,
          auth_data_, pkcs11init.GetTpmTokenLabelForUser(username_),
          &slot_id)) {
    LOG(ERROR) << "Failed to load PKCS #11 token.";
    ReportCryptohomeError(kLoadPkcs11TokenFailed);

    // We should not do it if we failed, but keep it to preserve the behaviour.
    auth_data_.clear();
    ready_ = true;

    return false;
  }

  auth_data_.clear();
  ready_ = true;

  return true;
}

void RealPkcs11Token::Remove() {
  ready_ = false;

  std::unique_ptr<chaps::TokenManagerClient> chaps_client(
      chaps_client_factory_->New());
  chaps_client->UnloadToken(
      IsolateCredentialManager::GetDefaultIsolateCredential(), token_dir_);
}

bool RealPkcs11Token::IsReady() const {
  return ready_;
}

}  // namespace cryptohome
