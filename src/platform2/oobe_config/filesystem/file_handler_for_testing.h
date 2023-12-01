// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_FOR_TESTING_H_
#define OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_FOR_TESTING_H_

#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/files/file_path.h>

#include "oobe_config/filesystem/file_handler.h"

namespace oobe_config {

// Each `FileHandlerForTesting` object creates and manages its own temporary
// directory. It is safe to copy-construct a `FileHandler` from it, as that will
// only copy the path, but not duplicate lifetime-management of the path.
class FileHandlerForTesting : public FileHandler {
 public:
  FileHandlerForTesting();
  FileHandlerForTesting(FileHandlerForTesting&&) noexcept;
  FileHandlerForTesting& operator=(FileHandlerForTesting&&) noexcept;

  FileHandlerForTesting(const FileHandlerForTesting&) = delete;
  FileHandlerForTesting& operator=(const FileHandlerForTesting&) = delete;

  ~FileHandlerForTesting() override;

  // Creates the paths that exists by default and are relevant to oobe_config.
  bool CreateDefaultExistingPaths() const;

  // Creates path for oobe_config_restore.
  bool CreateRestorePath() const;
  // Creates path for oobe_config_save
  bool CreateSavePath() const;
  // Creates powerwash-safe path.
  bool CreatePreservePath() const;
  // Creates the path that is normally created by pstore on boot.
  bool CreateRamoopsPath() const;
  // Creates /home/chronos.
  bool CreateChronosPath() const;

  // Checks if the flag that indicates oobe_config_save ran successfully exists.
  bool HasDataSavedFlag() const;

  // Places the flag that indicates oobe is completed in oobe_config_save
  // directory.
  bool CreateOobeCompletedFlag() const;

  // Creates the file that indicates metrics reporting is enabled. Usually it
  // contains an Id, but rollback does not save or care about the Id, so placing
  // and empty file for tests suffices.
  bool CreateMetricsReportingEnabledFile() const;

  // Removes the file that indicates metrics reporting is enabled.
  bool RemoveMetricsReportingEnabledFile() const;

  // Reads data staged to be preserved across powerwash in pstore from
  // oobe_config_save directory.
  bool ReadPstoreData(std::string* data) const;

  // Writes the file that would be created if pstore had preserved `data` across
  // a reboot.
  bool WriteRamoopsData(const std::string& data) const;
  // Removes the file that pstore creates when it preserves data across a
  // reboot.
  bool RemoveRamoopsData() const;

  base::FilePath GetFullPath(
      const std::string& path_without_root) const override;

 private:
  static inline constexpr char kRamoops0FileName[] = "pmsg-ramoops-0";

  base::ScopedTempDir fake_root_dir_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_FILESYSTEM_FILE_HANDLER_FOR_TESTING_H_
