// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/encryption/verification.h"

#include <string>

#include <base/memory/scoped_refptr.h>
#include <base/strings/string_piece.h>

#include "missive/encryption/primitives.h"
#include "missive/util/dynamic_flag.h"
#include "missive/util/status.h"

namespace reporting {

namespace {

// Well-known public signature verification keys.
constexpr uint8_t kProdVerificationKey[kKeySize] = {
    0x51, 0x2D, 0x53, 0xA3, 0xF5, 0xEB, 0x01, 0xCE, 0xDA, 0xFC, 0x8E,
    0x79, 0xE7, 0x0F, 0xE1, 0x65, 0xDC, 0x14, 0x86, 0x53, 0x8B, 0x97,
    0x5A, 0x2D, 0x70, 0x08, 0xCB, 0xCA, 0x60, 0xC3, 0x55, 0xE6};

constexpr uint8_t kDevVerificationKey[kKeySize] = {
    0xC6, 0x2C, 0x4D, 0x25, 0x9E, 0x3E, 0x99, 0xA0, 0x2E, 0x08, 0x15,
    0x8C, 0x38, 0xB7, 0x6C, 0x08, 0xDF, 0xE7, 0x6E, 0x3A, 0xD6, 0x5A,
    0xC5, 0x58, 0x09, 0xE4, 0xAB, 0x89, 0x3A, 0x31, 0x53, 0x07};

}  // namespace

SignatureVerificationDevFlag::SignatureVerificationDevFlag(bool is_enabled)
    : DynamicFlag("signature_verification_dev", is_enabled) {}

// static
base::StringPiece SignatureVerifier::VerificationKey() {
  return base::StringPiece(reinterpret_cast<const char*>(kProdVerificationKey),
                           kKeySize);
}

// static
base::StringPiece SignatureVerifier::VerificationKeyDev() {
  return base::StringPiece(reinterpret_cast<const char*>(kDevVerificationKey),
                           kKeySize);
}

SignatureVerifier::SignatureVerifier(
    base::StringPiece verification_public_key,
    scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag)
    : verification_public_key_(verification_public_key),
      signature_verification_dev_flag_(signature_verification_dev_flag) {}

Status SignatureVerifier::Verify(base::StringPiece message,
                                 base::StringPiece signature) {
  std::string verification_key_dev = std::string(VerificationKeyDev());
  const std::string& verification_public_key =
      signature_verification_dev_flag_->is_enabled() ? verification_key_dev
                                                     : verification_public_key_;
  if (signature.size() != kSignatureSize) {
    return Status{error::FAILED_PRECONDITION, "Wrong signature size"};
  }
  if (verification_public_key.size() != kKeySize) {
    return Status{error::FAILED_PRECONDITION, "Wrong public key size"};
  }
  if (!VerifySignature(
          reinterpret_cast<const uint8_t*>(verification_public_key.data()),
          message, reinterpret_cast<const uint8_t*>(signature.data()))) {
    return Status{error::INVALID_ARGUMENT, "Verification failed"};
  }

  return Status::StatusOK();
}

}  // namespace reporting
