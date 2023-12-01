// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Standalone tool that executes tests on a live TPM.

#include <cstdlib>

#include <base/at_exit.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <openssl/evp.h>

#include "cryptohome/tpm_live_test.h"

class ClientLoop : public brillo::Daemon {
 public:
  explicit ClientLoop(const std::string& test) : test_(test) {}

 protected:
  int OnEventLoopStarted() override {
    bool success = false;
    if (test_.empty()) {
      LOG(ERROR) << "--test is required.";
    } else if (test_ == "tpm_ecc_auth_block_test") {
      cryptohome::TpmLiveTest().TpmEccAuthBlockTest(base::BindOnce(
          &ClientLoop::TPMPasswordAuthCallback, weak_factory_.GetWeakPtr()));
      return EXIT_SUCCESS;
    } else if (test_ == "tpm_bound_to_pcr_auth_block_test") {
      cryptohome::TpmLiveTest().TpmBoundToPcrAuthBlockTest(base::BindOnce(
          &ClientLoop::TPMPasswordAuthCallback, weak_factory_.GetWeakPtr()));
      return EXIT_SUCCESS;
    } else if (test_ == "tpm_not_bound_to_pcr_auth_block_test") {
      cryptohome::TpmLiveTest().TpmNotBoundToPcrAuthBlockTest(base::BindOnce(
          &ClientLoop::TPMPasswordAuthCallback, weak_factory_.GetWeakPtr()));
      return EXIT_SUCCESS;
    } else if (test_ == "decryption_key_test") {
      success = cryptohome::TpmLiveTest().DecryptionKeyTest();
    } else if (test_ == "seal_with_current_user_test") {
      success = cryptohome::TpmLiveTest().SealWithCurrentUserTest();
    } else if (test_ == "signature_sealed_secret_test") {
      success = cryptohome::TpmLiveTest().SignatureSealedSecretTest();
    } else if (test_ == "recovery_tpm_backend_test") {
      success = cryptohome::TpmLiveTest().RecoveryTpmBackendTest();
    } else {
      LOG(ERROR) << "Unknown --test.";
    }

    QuitWithExitCode(success ? EXIT_SUCCESS : EXIT_FAILURE);
    return EXIT_SUCCESS;
  }

 private:
  void TPMPasswordAuthCallback(bool success) {
    QuitWithExitCode(success ? EXIT_SUCCESS : EXIT_FAILURE);
  }
  std::string test_;
  base::WeakPtrFactory<ClientLoop> weak_factory_{this};
};

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToStderr);
  base::AtExitManager exit_manager;

  DEFINE_string(
      test, "",
      "One of: tpm_ecc_auth_block_test, "
      "tpm_bound_to_pcr_auth_block_test, tpm_not_bound_to_pcr_auth_block_test, "
      "pcr_key_test, decryption_key_test, seal_with_current_user_test,"
      "nvram_test, signature_sealed_secret_test,"
      "recovery_tpm_backend_test.");

  brillo::FlagHelper::Init(argc, argv,
                           "Executes cryptohome tests on a live TPM.\nNOTE: "
                           "the TPM must be available and owned.");

  OpenSSL_add_all_algorithms();
  LOG(INFO) << "Running TPM live tests.";

  ClientLoop loop(FLAGS_test);
  return loop.Run();
}
