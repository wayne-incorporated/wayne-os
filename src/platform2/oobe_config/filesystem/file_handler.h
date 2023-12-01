// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_H_
#define OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_H_

#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>

namespace oobe_config {

// Wraps all file system access for oobe_config.
// Ideally, all writing or reading access to folders and files should be done
// through this class. This allows for faking or using temporary directories in
// tests. See `FileHandlerForTesting` class. Relevant path names are:
// - Powerwash-safe directory: /mnt/stateful_partition/unencrypted/preserve
// - oobe_config_save directory: /var/lib/oobe_config_save
// - oobe_config_restore directory: /var/lib/oobe_config_restore
// Everything below /var is encrypted stateful.
class FileHandler {
 public:
  explicit FileHandler(const std::string& root_directory = "/");
  FileHandler(const FileHandler&);
  FileHandler(FileHandler&&) noexcept;
  FileHandler& operator=(const FileHandler&);
  FileHandler& operator=(FileHandler&&) noexcept;

  virtual ~FileHandler();

  // Checks if the folder in encrypted stateful used by oobe_config_restore
  // exists.
  bool HasRestorePath() const;
  // Removes the folder in encrypted stateful used by oobe_config_restore.
  bool RemoveRestorePath() const;

  // Checks if OpenSSL encrypted rollback data in powerwash-safe directory
  // exists.
  bool HasOpensslEncryptedRollbackData() const;
  // Reads OpenSSL encrypted rollback data from powerwash-safe directory
  bool ReadOpensslEncryptedRollbackData(
      std::string* openssl_encrypted_rollback_data) const;
  // Writes OpenSSL encrypted rollback data to powerwash-safe directory.
  bool WriteOpensslEncryptedRollbackData(
      const std::string& openssl_encrypted_rollback_data) const;
  // Removes OpenSSL encrypted rollback data in powerwash-safe directory.
  bool RemoveOpensslEncryptedRollbackData() const;

  // Checks if TPM encrypted rollback data in powerwash-safe directory
  // exists.
  bool HasTpmEncryptedRollbackData() const;
  // Reads TPM encrypted rollback data from powerwash-safe directory
  bool ReadTpmEncryptedRollbackData(
      std::string* tpm_encrypted_rollback_data) const;
  // Writes TPM encrypted rollback data to powerwash-safe directory.
  bool WriteTpmEncryptedRollbackData(
      const std::string& tpm_encrypted_rollback_data) const;
  // Removes TPM encrypted rollback data in powerwash-safe directory.
  bool RemoveTpmEncryptedRollbackData() const;

  // Checks if decrypted rollback data in oobe_config_restore directory exists.
  bool HasDecryptedRollbackData() const;
  // Reads decrypted rollback data from oobe_config_restore directory.
  bool ReadDecryptedRollbackData(std::string* decrypted_rollback_data) const;
  // Writes decrypted rollback data to oobe_config_restore directory.
  bool WriteDecryptedRollbackData(
      const std::string& decrypted_rollback_data) const;
  // Removes decrypted rollback data from oobe_config_restore directory.
  bool RemoveDecryptedRollbackData() const;

  // Checks if the flag that triggers oobe_config_save to run on shutdown
  // exists.
  bool HasRollbackSaveTriggerFlag() const;
  // Removes the flag that triggers oobe_config_save to run on shutdown.
  bool RemoveRollbackSaveTriggerFlag() const;

  // Places the flag that indicates oobe_config_save ran successfully.
  bool CreateDataSavedFlag() const;

  // Checks if the flag that indicates oobe is completed exists in
  // oobe_config_save directory.
  bool HasOobeCompletedFlag() const;

  // Checks if the flag that indicates metrics reporting is enabled exists in
  // oobe_config_save directory.
  bool HasMetricsReportingEnabledFlag() const;

  // Writes data to be preserved by pstore across powerwash into
  // oobe_config_save directory.
  bool WritePstoreData(const std::string& data) const;

  // Checks if rollback metrics data exists.
  bool HasRollbackMetricsData() const;
  // Reads rollback metrics data file.
  bool ReadRollbackMetricsData(std::string* rollback_metrics_data) const;
  // Writes rollback metrics data file.
  bool WriteRollbackMetricsData(const std::string& rollback_metrics_data) const;
  // Removes rollback metrics data file.
  bool RemoveRollbackMetricsData() const;

  // Returns a file enumerator to contents of pstore after reboot.
  base::FileEnumerator RamoopsFileEnumerator() const;

 protected:
  static constexpr char kPreservePath[] =
      "mnt/stateful_partition/unencrypted/preserve";
  static constexpr char kDataRestorePath[] = "var/lib/oobe_config_restore";
  static constexpr char kDataSavePath[] = "var/lib/oobe_config_save";
  static constexpr char kChronosPath[] = "home/chronos";

  static constexpr char kSaveRollbackDataFile[] =
      "mnt/stateful_partition/.save_rollback_data";

  static constexpr char kDecryptedRollbackDataFileName[] = "rollback_data";
  static constexpr char kOpensslEncryptedRollbackDataFileName[] =
      "rollback_data";
  static constexpr char kTpmEncryptedRollbackDataFileName[] =
      "rollback_data_tpm";
  static constexpr char kDataSavedFileName[] = ".data_saved";

  static constexpr char kOobeCompletedFileName[] = ".oobe_completed";
  static constexpr char kMetricsReportingEnabledFileName[] =
      "Consent To Send Stats";

  static constexpr char kRamoopsFilePattern[] = "pmsg-ramoops-*";
  static constexpr char kRamoopsPath[] = "sys/fs/pstore/";
  static constexpr char kPstoreFileName[] = "data_for_pstore";

  static constexpr char kRollbackMetricsDataFileName[] =
      "enterprise-rollback-metrics-data";

  virtual base::FilePath GetFullPath(
      const std::string& path_without_root) const;

  base::FilePath root_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_H_
