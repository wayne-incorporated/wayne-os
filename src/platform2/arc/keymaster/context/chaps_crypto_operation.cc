// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/chaps_crypto_operation.h"

#include <chaps/pkcs11/cryptoki.h>

#include <optional>

#include <base/logging.h>

#include "arc/keymaster/context/chaps_client.h"
#include "arc/keymaster/context/context_adaptor.h"

namespace arc {
namespace keymaster {
namespace context {

constexpr MechanismDescription kCkmRsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kNone, Padding ::kPkcs1,
    BlockMode::kNone};

constexpr MechanismDescription kCkmMd5RsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kMd5, Padding ::kPkcs1,
    BlockMode::kNone};

constexpr MechanismDescription kCkmSha1RsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kSha1, Padding ::kPkcs1,
    BlockMode::kNone};

constexpr MechanismDescription kCkmSha256RsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kSha256, Padding ::kPkcs1,
    BlockMode::kNone};

constexpr MechanismDescription kCkmSha384RsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kSha384, Padding ::kPkcs1,
    BlockMode::kNone};

constexpr MechanismDescription kCkmSha512RsaPkcsSign = {
    OperationType::kSign, Algorithm::kRsa, Digest::kSha512, Padding ::kPkcs1,
    BlockMode::kNone};

ChapsCryptoOperation::ChapsCryptoOperation(
    base::WeakPtr<ContextAdaptor> context_adaptor,
    ContextAdaptor::Slot slot,
    const std::string& label,
    const brillo::Blob& id)
    : context_adaptor_(context_adaptor), slot_(slot), label_(label), id_(id) {}

ChapsCryptoOperation::~ChapsCryptoOperation() = default;

bool ChapsCryptoOperation::IsSupportedMechanism(
    MechanismDescription description) const {
  return kCkmRsaPkcsSign == description || kCkmMd5RsaPkcsSign == description ||
         kCkmSha1RsaPkcsSign == description ||
         kCkmSha256RsaPkcsSign == description ||
         kCkmSha384RsaPkcsSign == description ||
         kCkmSha512RsaPkcsSign == description;
}

std::optional<uint64_t> ChapsCryptoOperation::Begin(
    MechanismDescription mechanism_description) {
  if (!IsSupportedMechanism(mechanism_description)) {
    LOG(ERROR) << "Mechanism not implemented for chaps keys: "
               << mechanism_description;
    return std::nullopt;
  }
  set_description(mechanism_description);

  chaps_ = std::make_unique<ChapsClient>(context_adaptor_, slot_);
  std::optional<CK_OBJECT_HANDLE> handle =
      chaps_->FindObject(CKO_PRIVATE_KEY, label_, id_);
  if (!handle.has_value())
    return std::nullopt;

  CK_OBJECT_HANDLE key_handle = handle.value();

  bool success = false;

  if (description() == kCkmRsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_RSA_PKCS, key_handle);
  } else if (description() == kCkmMd5RsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_MD5_RSA_PKCS, key_handle);
  } else if (description() == kCkmSha1RsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_SHA1_RSA_PKCS, key_handle);
  } else if (description() == kCkmSha256RsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_SHA256_RSA_PKCS, key_handle);
  } else if (description() == kCkmSha384RsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_SHA384_RSA_PKCS, key_handle);
  } else if (description() == kCkmSha512RsaPkcsSign) {
    success = chaps_->InitializeSignature(CKM_SHA512_RSA_PKCS, key_handle);
  } else {
    LOG(ERROR) << "Unsupported operation " << description();
  }

  return success ? chaps_->session_handle() : std::nullopt;
}

std::optional<brillo::Blob> ChapsCryptoOperation::Update(
    const brillo::Blob& input) {
  switch (description().type) {
    case OperationType::kSign:
      return chaps_->UpdateSignature(input)
                 ? std::optional<brillo::Blob>(brillo::Blob())
                 : std::nullopt;
    case OperationType::kUnsupported:
      return std::nullopt;
  }
}

std::optional<brillo::Blob> ChapsCryptoOperation::Finish() {
  std::optional<brillo::Blob> result;

  switch (description().type) {
    case OperationType::kSign:
      result = chaps_->FinalizeSignature();
      break;
    case OperationType::kUnsupported:
      result = std::nullopt;
      break;
  }

  chaps_.reset();
  return result;
}

bool ChapsCryptoOperation::Abort() {
  chaps_.reset();
  return true;
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
