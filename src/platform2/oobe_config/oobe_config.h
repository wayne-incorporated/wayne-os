// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_OOBE_CONFIG_H_
#define OOBE_CONFIG_OOBE_CONFIG_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <libhwsec/factory/factory_impl.h>

#include "oobe_config/filesystem/file_handler.h"

namespace oobe_config {

class RollbackData;

// Helper class for saving and restoring rollback data.
class OobeConfig {
 public:
  explicit OobeConfig(hwsec::OobeConfigFrontend* hwsec_oobe_config,
                      FileHandler file_handler = FileHandler());
  OobeConfig(const OobeConfig&) = delete;
  OobeConfig& operator=(const OobeConfig&) = delete;

  ~OobeConfig();

  // Saves the rollback data into an encrypted file. Returns true on success.
  bool EncryptedRollbackSave(bool run_tpm_encryption = false) const;

  // Restores the rollback data from an encrypted file. Returns true on success.
  bool EncryptedRollbackRestore() const;

  // Sets a network config which is used instead of requesting network
  // configuration via mojo from Chrome.
  void set_network_config_for_testing(const std::string& config) {
    network_config_for_testing_ = config;
  }

 private:
  // Checks if rollback space in TPM exists. Returns false on failure to check,
  // or if the space does not exist.
  bool TpmRollbackSpaceReady() const;

  // Attempts to encrypt and save TPM encrypted rollback data and saves it into
  // `rollback_data_tpm` file.
  // Expects the empty file to write to and rollback space to exist. Returns
  // false on failure.
  bool TpmEncryptedRollbackSave(const std::string& rollback_data) const;

  // Attempts to encrypt and save OpenSSL encrypted rollback data and saves it
  // into `rollback_data` file.
  // Expects the file to write to to exists already. Returns false on failure.
  bool OpenSslEncryptedRollbackSave(const std::string& rollback_data) const;

  // Attempts to load and decrypt data with TPM. Returns `std::nullopt` on
  // failure. Expects the rollback space to exist.
  std::optional<brillo::SecureBlob> TpmEncryptedRollbackRestore() const;

  // Attempts to load and decrypt data with OpenSSL. Returns `std::nullopt` on
  // failure, if the key cannot be loaded, or the data does not exist.
  std::optional<brillo::SecureBlob> OpensslEncryptedRollbackRestore() const;

  // Gets the files needed for rollback and stores them in a |RollbackData|
  // proto, then returns the serialized proto |serialized_rollback_data|.
  bool GetSerializedRollbackData(std::string* serialized_rollback_data) const;

  // Gets the files needed for rollback and returns them in |rollback_data|.
  void GetRollbackData(RollbackData* rollback_data) const;

  // Object for accessing the HWSec related functions.
  hwsec::OobeConfigFrontend* hwsec_oobe_config_;
  // Object for managing files.
  FileHandler file_handler_;

  // Network configuration to be used in unit tests instead of requesting
  // network configuration from Chrome.
  std::string network_config_for_testing_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_OOBE_CONFIG_H_
