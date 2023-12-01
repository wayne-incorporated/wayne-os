// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_TEST_UTILS_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_TEST_UTILS_H_

#include <utility>

#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec/frontend/recovery_crypto/mock_frontend.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/crypto.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Helper methods and common constants for writing metadata-oriented tests.
class AuthFactorDriverGenericTest : public ::testing::Test {
 protected:
  // Useful generic constants to use for usernames.
  const Username kUser{"user"};
  const ObfuscatedUsername kObfuscatedUser{
      brillo::cryptohome::home::SanitizeUserName(kUser)};

  // Useful generic constants to use for labels and version metadata.
  static constexpr char kLabel[] = "some-label";
  static constexpr char kChromeosVersion[] = "1.2.3_a_b_c";
  static constexpr char kChromeVersion[] = "1.2.3.4";

  // Create a generic metadata with the given factor-specific subtype using
  // version information from the test. The 0-arg version will create a default
  // version of the type-specific metadata, while the 1-arg version allows you
  // to specify it instead.
  template <typename MetadataType>
  AuthFactorMetadata CreateMetadataWithType() {
    return {
        .common = {.chromeos_version_last_updated = kChromeosVersion,
                   .chrome_version_last_updated = kChromeVersion},
        .metadata = MetadataType(),
    };
  }
  template <typename MetadataType>
  AuthFactorMetadata CreateMetadataWithType(MetadataType type_specific) {
    return {
        .common = {.chromeos_version_last_updated = kChromeosVersion,
                   .chrome_version_last_updated = kChromeVersion},
        .metadata = std::move(type_specific),
    };
  }

  // Set up a task environment and test runner to make things easier for tests
  // which need to do async stuff (e.g. they can use TestFuture).
  base::test::SingleThreadTaskEnvironment task_environment_ = {
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<base::SequencedTaskRunner> task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();

  // A mock-based Crypto object, a common dependency for a lot of drivers.
  hwsec::MockCryptohomeFrontend hwsec_;
  hwsec::MockPinWeaverFrontend pinweaver_;
  MockCryptohomeKeysManager cryptohome_keys_manager_;
  hwsec::MockRecoveryCryptoFrontend recovery_frontend_;
  Crypto crypto_{&hwsec_, &pinweaver_, &cryptohome_keys_manager_,
                 &recovery_frontend_};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_TEST_UTILS_H_
