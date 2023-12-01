// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/encryption/encryption_module_interface.h"

#include <atomic>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>

#include "missive/proto/record.pb.h"
#include "missive/util/dynamic_flag.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

EncryptionModuleInterface::EncryptionModuleInterface(
    bool is_enabled, base::TimeDelta renew_encryption_key_period)
    : DynamicFlag("encryption", is_enabled),
      renew_encryption_key_period_(renew_encryption_key_period) {}

EncryptionModuleInterface::~EncryptionModuleInterface() = default;

void EncryptionModuleInterface::EncryptRecord(
    base::StringPiece record,
    base::OnceCallback<void(StatusOr<EncryptedRecord>)> cb) const {
  if (!is_enabled()) {
    // Encryptor disabled.
    EncryptedRecord encrypted_record;
    encrypted_record.mutable_encrypted_wrapped_record()->assign(record.begin(),
                                                                record.end());
    // encryption_info is not set.
    std::move(cb).Run(std::move(encrypted_record));
    return;
  }

  // Encryptor enabled: start encryption of the record as a whole.
  if (!has_encryption_key()) {
    // Encryption key is not available.
    std::move(cb).Run(
        Status(error::NOT_FOUND, "Cannot encrypt record - no key"));
    return;
  }
  // Encryption key is available, encrypt.
  EncryptRecordImpl(record, std::move(cb));
}

void EncryptionModuleInterface::UpdateAsymmetricKey(
    base::StringPiece new_public_key,
    PublicKeyId new_public_key_id,
    base::OnceCallback<void(Status)> response_cb) {
  UpdateAsymmetricKeyImpl(
      new_public_key, new_public_key_id,
      base::BindOnce(
          [](EncryptionModuleInterface* encryption_module_interface,
             base::OnceCallback<void(Status)> response_cb, Status status) {
            if (status.ok()) {
              encryption_module_interface->last_encryption_key_update_.store(
                  base::TimeTicks::Now());
            }
            std::move(response_cb).Run(status);
          },
          base::Unretained(this), std::move(response_cb)));
}

bool EncryptionModuleInterface::has_encryption_key() const {
  return !last_encryption_key_update_.load().is_null();
}

bool EncryptionModuleInterface::need_encryption_key() const {
  return !has_encryption_key() ||
         last_encryption_key_update_.load() + renew_encryption_key_period_ <
             base::TimeTicks::Now();
}

}  // namespace reporting
