// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/crypto_operation.h"

namespace arc {
namespace keymaster {
namespace context {

namespace {

constexpr char kNone[] = "none";
constexpr char kUnsupported[] = "unsupported";

}  // namespace

MechanismDescription::MechanismDescription(const MechanismDescription& other) =
    default;

MechanismDescription& MechanismDescription::operator=(
    const MechanismDescription& other) = default;

bool MechanismDescription::operator==(const MechanismDescription& other) const {
  return type == other.type && algorithm == other.algorithm &&
         digest == other.digest && padding == other.padding &&
         block_mode == other.block_mode;
}

bool MechanismDescription::operator<(const MechanismDescription& other) const {
  return type < other.type || algorithm < other.algorithm ||
         digest < other.digest || padding < other.padding ||
         block_mode < other.block_mode;
}

CryptoOperation::CryptoOperation() = default;

CryptoOperation::~CryptoOperation() = default;

std::ostream& operator<<(std::ostream& os,
                         MechanismDescription const& description) {
  os << "{type=";
  switch (description.type) {
    case OperationType::kSign:
      os << "sign";
      break;
    case OperationType::kUnsupported:
      os << kUnsupported;
      break;
  }

  os << ", algorithm=";
  switch (description.algorithm) {
    case Algorithm::kRsa:
      os << "RSA";
      break;
    case Algorithm::kUnsupported:
      os << kUnsupported;
      break;
  }

  os << ", digest=";
  switch (description.digest) {
    case Digest::kMd5:
      os << "MD5";
      break;
    case Digest::kSha1:
      os << "SHA1";
      break;
    case Digest::kSha256:
      os << "SHA256";
      break;
    case Digest::kSha384:
      os << "SHA384";
      break;
    case Digest::kSha512:
      os << "SHA512";
      break;
    case Digest::kNone:
      os << kNone;
      break;
    case Digest::kUnsupported:
      os << kUnsupported;
      break;
  }

  os << ", padding=";
  switch (description.padding) {
    case Padding::kPkcs7:
      os << "PKCS7";
      break;
    case Padding::kPkcs1:
      os << "PKCS1";
      break;
    case Padding::kNone:
      os << kNone;
      break;
    case Padding::kUnsupported:
      os << kUnsupported;
      break;
  }

  os << ", blockmode=";
  switch (description.block_mode) {
    case BlockMode::kCbc:
      os << "CBC";
      break;
    case BlockMode::kNone:
      os << kNone;
      break;
    case BlockMode::kUnsupported:
      os << kUnsupported;
      break;
  }
  return os << "}";
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
