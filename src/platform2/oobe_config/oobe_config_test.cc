// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/oobe_config_test.h"

#include <memory>
#include <string>
#include <utility>
#include <unistd.h>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/oobe_config/frontend.h>

#include "libhwsec/error/tpm_retry_action.h"
#include "oobe_config/filesystem/file_handler.h"
#include "oobe_config/oobe_config.h"
#include "oobe_config/rollback_data.pb.h"

namespace {
constexpr char kNetworkConfig[] = R"({"NetworkConfigurations":[{
    "GUID":"wpa-psk-network-guid",
    "Type": "WiFi",
    "Name": "WiFi",
    "WiFi": {
      "Security": "WPA-PSK",
      "Passphrase": "wpa-psk-network-passphrase"
  }}]})";

constexpr uint32_t kRollbackSpaceIndex = 0x100e;
constexpr uint32_t kRollbackSpaceSize = 32;
}  // namespace

namespace oobe_config {

void OobeConfigTest::SetUp() {
  hwsec_oobe_config_ = hwsec_factory_.GetOobeConfigFrontend();
  ASSERT_TRUE(file_handler_.CreateDefaultExistingPaths());

  oobe_config_ =
      std::make_unique<OobeConfig>(hwsec_oobe_config_.get(), file_handler_);
  oobe_config_->set_network_config_for_testing(kNetworkConfig);

  // Check that the TPM space does not exist for tests. All tests work under the
  // assumption that they need to create the space if they want to use it.
  ASSERT_TRUE(hwsec_oobe_config_->IsRollbackSpaceReady()->ToTPMRetryAction() ==
              hwsec::TPMRetryAction::kSpaceNotFound);
}

void OobeConfigTest::SimulatePowerwash(bool preserve_openssl,
                                       bool preserve_tpm) {
  bool has_tpm_file = false;
  std::string rollback_data_str_tpm = "";
  if (preserve_tpm) {
    // This file may not exist, failure to read is ok.
    has_tpm_file =
        file_handler_.ReadTpmEncryptedRollbackData(&rollback_data_str_tpm);
  }

  std::string rollback_data_str = "";
  std::string pstore_data = "";
  if (preserve_openssl) {
    ASSERT_TRUE(
        file_handler_.ReadOpensslEncryptedRollbackData(&rollback_data_str));

    ASSERT_TRUE(file_handler_.ReadPstoreData(&pstore_data));
  }

  file_handler_ = FileHandlerForTesting();
  oobe_config_ =
      std::make_unique<OobeConfig>(hwsec_oobe_config_.get(), file_handler_);
  ASSERT_TRUE(file_handler_.CreateDefaultExistingPaths());

  if (preserve_openssl) {
    ASSERT_TRUE(
        file_handler_.WriteOpensslEncryptedRollbackData(rollback_data_str));
    ASSERT_TRUE(file_handler_.WriteRamoopsData(pstore_data));
  }

  if (preserve_tpm && has_tpm_file) {
    ASSERT_TRUE(
        file_handler_.WriteTpmEncryptedRollbackData(rollback_data_str_tpm));
  }
}

void OobeConfigTest::CreateRollbackSpace() {
  ASSERT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kRollbackSpaceIndex, kRollbackSpaceSize));
  ASSERT_TRUE(hwsec_oobe_config_->IsRollbackSpaceReady().ok());
}

// Test are grouped into three categories.

// 1. Tests that fake rollback to and from this version of the code, TPM-based
//     encryption is possible but not activated. TPM space may exist, but it's
//     not used.

// No TPM space and no TPM based encryption activated. Decryption with OpenSSL
// works until we lose the key in pstore.
TEST_F(OobeConfigTest, OpensslEncryptionWorksUntilKeyIsLost) {
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
  ASSERT_TRUE(file_handler_.RemoveRamoopsData());
  ASSERT_FALSE(oobe_config_->EncryptedRollbackRestore());
}

// Decryption fails if no data is preserved.
TEST_F(OobeConfigTest, DecryptionFailsIfNoDataIsPreserved) {
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash(/*preserve_openssl=*/false, /*preserve_tpm=*/false);
  ASSERT_FALSE(oobe_config_->EncryptedRollbackRestore());
}

// Check that rollback data is assembled and preserved without TPM space.
TEST_F(OobeConfigTest, RollbackDataWithoutTpmSpace) {
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());

  std::string rollback_data_str;
  ASSERT_TRUE(file_handler_.ReadDecryptedRollbackData(&rollback_data_str));
  RollbackData rollback_data;
  ASSERT_TRUE(rollback_data.ParseFromString(rollback_data_str));

  ASSERT_FALSE(rollback_data.eula_auto_accept());
  ASSERT_FALSE(rollback_data.eula_send_statistics());
  ASSERT_EQ(rollback_data.network_config(), kNetworkConfig);
}

// Tests that use rollback space only run with TPM2.
#if USE_TPM2
// As of right now, only OpenSSL encryption is used, even if rollback space
// exists. This test does not ensure we do not run TPM encryption, it just
// checks the encryption and decryption will work with how powerwash is
// currently implemented.
TEST_F(OobeConfigTest, TpmSpaceButDoNotUse) {
  CreateRollbackSpace();
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// Make sure that even if TPM space exists, OpenSSL encryption is used if
// TPM-based encryption is not requested.
TEST_F(OobeConfigTest, OpensslWorksEvenIfTpmSpaceExists) {
  CreateRollbackSpace();
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash(/*preserve_openssl=*/true, /*preserve_tpm=*/false);
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}
#endif  // USE_TPM2

// 2. Tests that fake rollback to a version that does not know about TPM-based
//    encryption.

// An older version of the code will only preserve OpenSSL decrypted file.
TEST_F(OobeConfigTest, OpensslEncryptionToOldVersionWorks) {
  ASSERT_TRUE(
      oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/false));
  SimulatePowerwash(/*preserve_openssl=*/true, /*preserve_tpm=*/false);
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
  // Openssl data can be decrypted multiple times. Until we delete pstore data.
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// Tests that use rollback space only run with TPM2.
#if USE_TPM2
// When rolling back to a version pre-dating this code, TPM space may exist but
// is not used by the old code. Check that rollback from future code to old code
// will work.
TEST_F(OobeConfigTest, RollbackFromThisCodeToOldCode) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash(/*preserve_openssl=*/true, /*preserve_tpm=*/false);
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}
#endif  // USE_TPM2

// 3. Tests that fake rollback coming from a version of this code that runs
//    TPM-based encryption if possible, and leaves out OpenSSL encryption if TPM
//    based encryption can be used.

TEST_F(OobeConfigTest, OpenSSLWorksInTheFutureIfNoTpmSpaceExists) {
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// Tests that use rollback space only run with TPM2.
#if USE_TPM2
// On device with TPM space, encryption and decryption works.
TEST_F(OobeConfigTest, EncryptionWithTpmSpace) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// The first decrypt uses TPM decryption, the second one will fall back to the
// (still working) OpenSSL decryption.
TEST_F(OobeConfigTest, DecryptTwiceWithTpmSpace) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// On device with TPM space, we fall back to OpenSSL decryption if TPM-based
// decryption fails. In this test, TPM space is zeroed before decryption can
// take place.
TEST_F(OobeConfigTest, FallBackToOpenSSLIfSpaceIsReset) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash();
  ASSERT_TRUE(hwsec_oobe_config_->ResetRollbackSpace().ok());
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
}

// Future version of this code will only create the file encrypted
// with TPM (if rollback space exists). Make sure current code could handle
// that.
TEST_F(OobeConfigTest, TpmBasedEncryptionForcedSucceedsOnce) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash(/*preserve_openssl=*/false, /*preserve_tpm=*/true);
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());
  // TPM-based encryption only allows you to decrypt once. Then it resets the
  // space.
  ASSERT_FALSE(oobe_config_->EncryptedRollbackRestore());
}

// If the TPM space is zeroed before data can be decrypted,
// fallback to OpenSSL isn't possible, so restore will fail.
TEST_F(OobeConfigTest, DecryptFailsIfSpaceIsZeroed) {
  CreateRollbackSpace();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash(/*preserve_openssl=*/false, /*preserve_tpm=*/true);
  ASSERT_TRUE(hwsec_oobe_config_->ResetRollbackSpace().ok());
  ASSERT_FALSE(oobe_config_->EncryptedRollbackRestore());
}

// Check that rollback data is assembled and preserved with TPM space.
TEST_F(OobeConfigTest, RollbackDataWithTpmSpace) {
  CreateRollbackSpace();

  file_handler_.CreateOobeCompletedFlag();
  file_handler_.CreateMetricsReportingEnabledFile();

  ASSERT_TRUE(oobe_config_->EncryptedRollbackSave(/*run_tpm_encryption=*/true));
  SimulatePowerwash();
  ASSERT_TRUE(oobe_config_->EncryptedRollbackRestore());

  std::string rollback_data_str;
  ASSERT_TRUE(file_handler_.ReadDecryptedRollbackData(&rollback_data_str));
  RollbackData rollback_data;
  ASSERT_TRUE(rollback_data.ParseFromString(rollback_data_str));

  ASSERT_TRUE(rollback_data.eula_auto_accept());
  ASSERT_TRUE(rollback_data.eula_send_statistics());
  ASSERT_EQ(rollback_data.network_config(), kNetworkConfig);
}
#endif  // USE_TPM2

}  // namespace oobe_config
