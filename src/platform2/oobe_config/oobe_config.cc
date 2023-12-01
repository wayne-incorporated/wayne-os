// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/oobe_config.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec/status.h>

#include "libhwsec/frontend/oobe_config/frontend.h"
#include "oobe_config/encryption/openssl_encryption.h"
#include "oobe_config/encryption/pstore_storage.h"
#include "oobe_config/network_exporter.h"
#include "oobe_config/rollback_data.pb.h"

namespace oobe_config {

namespace {
void ResetRollbackSpace(hwsec::OobeConfigFrontend* hwsec_oobe_config) {
  hwsec::Status space_reset = hwsec_oobe_config->ResetRollbackSpace();
  if (!space_reset.ok()) {
    LOG(ERROR) << "Resetting rollback space failed: " << space_reset.status();
    // TODO(b/262235959): Report failure to reset rollback space.
  }
}
}  // namespace

OobeConfig::OobeConfig(hwsec::OobeConfigFrontend* hwsec_oobe_config,
                       FileHandler file_handler)
    : hwsec_oobe_config_(hwsec_oobe_config),
      file_handler_(std::move(file_handler)) {}

OobeConfig::~OobeConfig() = default;

void OobeConfig::GetRollbackData(RollbackData* rollback_data) const {
  if (file_handler_.HasOobeCompletedFlag()) {
    // If OOBE has been completed already, we know the EULA has been accepted.
    rollback_data->set_eula_auto_accept(true);
  }

  if (file_handler_.HasMetricsReportingEnabledFlag()) {
    rollback_data->set_eula_send_statistics(true);
  }

  if (network_config_for_testing_.empty()) {
    std::optional<std::string> network_config =
        oobe_config::ExportNetworkConfig();
    if (network_config.has_value()) {
      rollback_data->set_network_config(*network_config);
    }
  } else {
    rollback_data->set_network_config(network_config_for_testing_);
  }

  return;
}

bool OobeConfig::GetSerializedRollbackData(
    std::string* serialized_rollback_data) const {
  RollbackData rollback_data;
  GetRollbackData(&rollback_data);

  if (!rollback_data.SerializeToString(serialized_rollback_data)) {
    LOG(ERROR) << "Couldn't serialize proto.";
    return false;
  }

  return true;
}

bool OobeConfig::EncryptedRollbackSave(bool run_tpm_encryption) const {
  std::string serialized_rollback_data;
  if (!GetSerializedRollbackData(&serialized_rollback_data)) {
    return false;
  }

  // TODO(b/263065223): We are in migration stage 1. In production, only encrypt
  // data with OpenSSL. `run_tpm_encryption` is true during unit and tast tests.
  // This allows us to test TPM-based decryption works.
  if (run_tpm_encryption && TpmRollbackSpaceReady()) {
    TpmEncryptedRollbackSave(serialized_rollback_data);
  }
  bool openssl_success = OpenSslEncryptedRollbackSave(serialized_rollback_data);

  // While we run both encryptions, we consider success to save
  // OpenSSL-encrypted data success overall. If TPM-based encryption fails, we
  // can still run rollback successfully.
  if (!openssl_success)
    return false;

  if (!file_handler_.CreateDataSavedFlag()) {
    LOG(ERROR) << "Failed to write data saved flag.";
    return false;
  }

  return true;
}

bool OobeConfig::EncryptedRollbackRestore() const {
  std::optional<brillo::SecureBlob> decrypted_data;

  if (TpmRollbackSpaceReady()) {
    decrypted_data = TpmEncryptedRollbackRestore();
  }

  // Only attempt openssl decryption if tpm-based decryption didn't happen or
  // failed.
  if (!decrypted_data.has_value()) {
    decrypted_data = OpensslEncryptedRollbackRestore();
  }

  if (!decrypted_data.has_value()) {
    return false;
  }

  std::string rollback_data_str = decrypted_data->to_string();
  // Write the unencrypted data to disk.
  if (!file_handler_.WriteDecryptedRollbackData(rollback_data_str)) {
    return false;
  }

  return true;
}

bool OobeConfig::TpmRollbackSpaceReady() const {
  hwsec::Status space_ready = hwsec_oobe_config_->IsRollbackSpaceReady();

  if (!space_ready.ok()) {
    if (space_ready->ToTPMRetryAction() ==
        hwsec::TPMRetryAction::kSpaceNotFound) {
      // TODO(b/262235959): Maybe add a metric here, but make sure it is only
      // reported on data restore because data save reporting is unreliable.
      // Not finding space is expected, log as informational.
      LOG(INFO) << "Rollback space does not exist. Status: "
                << space_ready.status();
    } else {
      LOG(ERROR) << "Failed to check if rollback space exists. Status: "
                 << space_ready.status();
    }
    return false;
  }

  LOG(INFO) << "Rollback space found.";
  return true;
}

bool OobeConfig::TpmEncryptedRollbackSave(
    const std::string& rollback_data) const {
  DCHECK(TpmRollbackSpaceReady());

  LOG(INFO) << "Attempting encryption using rollback space.";

  hwsec::StatusOr<brillo::Blob> encrypted_rollback_data_tpm =
      hwsec_oobe_config_->Encrypt(brillo::SecureBlob(rollback_data));

  if (!encrypted_rollback_data_tpm.ok()) {
    LOG(ERROR) << "Falling back to openssl encryption. Status: "
               << encrypted_rollback_data_tpm.status();
    return false;
  }

  if (!file_handler_.WriteTpmEncryptedRollbackData(
          brillo::BlobToString(*encrypted_rollback_data_tpm))) {
    LOG(ERROR) << "Failed to write TPM-encrypted rollback data file. "
                  "Falling back to openssl encryption.";
    return false;
  }
  LOG(INFO) << "Finished TPM-based encryption.";
  return true;
}

bool OobeConfig::OpenSslEncryptedRollbackSave(
    const std::string& rollback_data) const {
  LOG(INFO) << "Attempting encryption using OpenSSL.";

  std::optional<EncryptedData> encrypted_rollback_data =
      Encrypt(brillo::SecureBlob(rollback_data));

  if (!encrypted_rollback_data) {
    LOG(ERROR) << "Failed to encrypt with openssl.";
    return false;
  }

  if (!StageForPstore(encrypted_rollback_data->key.to_string(),
                      file_handler_)) {
    LOG(ERROR)
        << "Failed to prepare data for storage in the encrypted reboot vault";
    return false;
  }

  if (!file_handler_.WriteOpensslEncryptedRollbackData(
          brillo::BlobToString(encrypted_rollback_data->data))) {
    LOG(ERROR) << "Failed to write openssl-encrypted rollback data file.";
    return false;
  }

  LOG(INFO) << "Successfully encrypted data with OpenSSL.";
  return true;
}

std::optional<brillo::SecureBlob> OobeConfig::TpmEncryptedRollbackRestore()
    const {
  DCHECK(TpmRollbackSpaceReady());

  LOG(INFO) << "Attempting decryption using rollback space.";

  std::string encrypted_data_tpm;
  if (!file_handler_.ReadTpmEncryptedRollbackData(&encrypted_data_tpm)) {
    LOG(WARNING)
        << "TPM has rollback space but found no TPM-encrypted rollback data "
           "file. This is expected if you did not request to encrypt with TPM.";
    // TODO(b/262235959): Report failure to find TPM-encrypted rollback data.
    ResetRollbackSpace(hwsec_oobe_config_);
    return std::nullopt;
  }

  hwsec::StatusOr<brillo::SecureBlob> decrypted_data_tpm =
      hwsec_oobe_config_->Decrypt(brillo::BlobFromString(encrypted_data_tpm));
  if (!decrypted_data_tpm.ok()) {
    LOG(WARNING) << "TPM decryption failed. This may happen in rare cases, "
                    "e.g. when TPM is cleared during rollback OOBE. Falling "
                    "back to OpenSSL decryption. Status: "
                 << decrypted_data_tpm.status();
    // TODO(b/262235959): Report failure to decrypt data with TPM.
    return std::nullopt;
  }
  LOG(INFO) << "Successfully decrypted TPM-encrypted rollback data.";
  // TODO(b/262235959): Report TPM-based encryption finished successfully.

  ResetRollbackSpace(hwsec_oobe_config_);

  return decrypted_data_tpm.value();
}

std::optional<brillo::SecureBlob> OobeConfig::OpensslEncryptedRollbackRestore()
    const {
  LOG(INFO) << "Attempting decryption using OpenSSL.";

  std::optional<std::string> key = LoadFromPstore(file_handler_);
  if (!key.has_value()) {
    LOG(ERROR) << "Failed to load key from pstore.";
    return std::nullopt;
  }

  std::string encrypted_data;
  if (!file_handler_.ReadOpensslEncryptedRollbackData(&encrypted_data)) {
    return std::nullopt;
  }

  std::optional<brillo::SecureBlob> decrypted_data = Decrypt(
      {brillo::BlobFromString(encrypted_data), brillo::SecureBlob(*key)});
  if (!decrypted_data.has_value()) {
    LOG(ERROR) << "Could not decrypt OpenSSL-encrypted rollback data.";
    return std::nullopt;
  }

  LOG(INFO) << "Successfully decrypted data with OpenSSL.";
  return decrypted_data;
}

}  // namespace oobe_config
