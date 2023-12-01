// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ENCRYPTION_VERIFICATION_H_
#define MISSIVE_ENCRYPTION_VERIFICATION_H_

#include <string>

#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/string_piece.h>

#include "missive/util/dynamic_flag.h"
#include "missive/util/status.h"

namespace reporting {

// When enabled DEV verification key will be used, otherwise PROD verification
// key will be used. This should be enabled for testing purposes in only in dev
// or testing environments.
class SignatureVerificationDevFlag
    : public DynamicFlag,
      public base::RefCountedThreadSafe<SignatureVerificationDevFlag> {
 public:
  explicit SignatureVerificationDevFlag(bool is_enabled);

  SignatureVerificationDevFlag(const SignatureVerificationDevFlag&) = delete;
  SignatureVerificationDevFlag& operator=(const SignatureVerificationDevFlag&) =
      delete;

 private:
  friend base::RefCountedThreadSafe<SignatureVerificationDevFlag>;
  ~SignatureVerificationDevFlag() override = default;
};

// Helper class that verifies an Ed25519 signed message received from
// the server. It uses boringssl implementation available on the client.
class SignatureVerifier {
 public:
  // Well-known public signature verification keys that is used to verify
  // that signed data is indeed originating from reporting server.
  // Exists in two flavors: PROD and DEV.
  static base::StringPiece VerificationKey();
  static base::StringPiece VerificationKeyDev();

  // Ed25519 |verification_public_key| must consist of kKeySize bytes.
  SignatureVerifier(base::StringPiece verification_public_key,
                    scoped_refptr<SignatureVerificationDevFlag>
                        signature_verification_dev_flag);

  // Actual verification - returns error status if provided |signature| does not
  // match |message|. Signature must be kSignatureSize bytes.
  Status Verify(base::StringPiece message, base::StringPiece signature);

 private:
  std::string verification_public_key_;

  scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag_;
};
}  // namespace reporting

#endif  // MISSIVE_ENCRYPTION_VERIFICATION_H_
