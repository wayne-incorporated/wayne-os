// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/test/test_timeouts.h>
#include <brillo/fake_cryptohome.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec/factory/fuzzed_factory.h>

#include "cryptohome/cryptorecovery/recovery_crypto_impl.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/fuzzers/fuzzed_platform.h"
#include "cryptohome/platform.h"

namespace cryptohome {
namespace {

constexpr char kStubSystemSalt[] = "stub-system-salt";

// Performs initialization.
class Environment {
 public:
  Environment() {
    base::CommandLine::Init(0, nullptr);
    TestTimeouts::Initialize();
    // Suppress logging from the code under test.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }

 private:
  // Initialize the system salt singleton with a stub value.
  brillo::cryptohome::home::FakeSystemSaltLoader system_salt_loader_{
      kStubSystemSalt};
};

}  // namespace

// Fuzz-tests the logic of Recovery_Id generation in
// |cryptorecovery::RecoveryCryptoImpl| that relies on external input read from
// the filesystem.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider provider(data, size);
  AccountIdentifier account_id;
  std::string user_id = provider.ConsumeRandomLengthString();
  account_id.set_account_id(user_id);

  // Prepare Recovery_Id's dependencies.
  FuzzedPlatform platform(provider);
  hwsec::FuzzedFactory hwsec_factory(provider);
  std::unique_ptr<const hwsec::RecoveryCryptoFrontend>
      recovery_crypto_fake_backend = hwsec_factory.GetRecoveryCryptoFrontend();
  std::unique_ptr<cryptorecovery::RecoveryCryptoImpl> recovery =
      cryptorecovery::RecoveryCryptoImpl::Create(
          recovery_crypto_fake_backend.get(), &platform);
  CHECK(recovery);
  if (recovery->GenerateRecoveryId(account_id)) {
    // Generating a recovery_id from file was successful - we can now load the
    // value that was stored.
    std::ignore = recovery->LoadStoredRecoveryId(account_id).empty();
  }

  return 0;
}

}  // namespace cryptohome
