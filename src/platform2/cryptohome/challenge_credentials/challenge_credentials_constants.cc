// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/challenge_credentials_constants.h"

#include <iterator>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/no_destructor.h>

using brillo::Blob;
using brillo::BlobFromString;

namespace cryptohome {

namespace {

// The constant prefix for the salt for challenge-protected credentials (see the
// comment on GetChallengeCredentialsSaltConstantPrefix() for details).
//
// For extra safety, this constant is made longer than 64 bytes and is
// terminated with a null character, following the safety measures made in TLS
// 1.3: https://tools.ietf.org/html/draft-ietf-tls-tls13-23#section-4.4.3 .
constexpr char kChallengeCredentialsSaltConstantPrefix[] =
    "Chrome OS challenge credentials salt Chrome OS challenge credentials "
    "salt\0";
static_assert(std::size(kChallengeCredentialsSaltConstantPrefix) > 64,
              "The salt prefix is too short");
static_assert(!kChallengeCredentialsSaltConstantPrefix
                  [std::size(kChallengeCredentialsSaltConstantPrefix) - 1],
              "The salt prefix must terminate with a null character");

}  // namespace

const int kChallengeCredentialsSaltRandomByteCount = 20;

const Blob& GetChallengeCredentialsSaltConstantPrefix() {
  static const base::NoDestructor<Blob> salt_constant_prefix(BlobFromString(
      std::string(std::begin(kChallengeCredentialsSaltConstantPrefix),
                  std::end(kChallengeCredentialsSaltConstantPrefix))));
  // Verify that we correctly converted the static character constant, without
  // losing the trailing null character.
  CHECK(!salt_constant_prefix->back());
  return *salt_constant_prefix;
}

}  // namespace cryptohome
