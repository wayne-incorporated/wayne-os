// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SECRET_STASH_MOCK_USER_METADATA_H_
#define CRYPTOHOME_USER_SECRET_STASH_MOCK_USER_METADATA_H_

#include "cryptohome/user_secret_stash/user_metadata.h"

#include <string>
#include <utility>

#include <gmock/gmock.h>

#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/username.h"

namespace cryptohome {

class MockUserMetadataReader : public UserMetadataReader {
 public:
  MockUserMetadataReader() : UserMetadataReader(nullptr) {}

  MOCK_METHOD(CryptohomeStatusOr<UserMetadata>,
              Load,
              (const ObfuscatedUsername&),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SECRET_STASH_MOCK_USER_METADATA_H_
