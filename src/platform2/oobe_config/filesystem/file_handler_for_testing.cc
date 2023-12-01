// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/filesystem/file_handler_for_testing.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>

#include "oobe_config/filesystem/file_handler.h"

namespace oobe_config {

FileHandlerForTesting::FileHandlerForTesting() {
  CHECK(fake_root_dir_.CreateUniqueTempDir());
  root_ = fake_root_dir_.GetPath();
}

FileHandlerForTesting::FileHandlerForTesting(FileHandlerForTesting&&) noexcept =
    default;
FileHandlerForTesting& FileHandlerForTesting::operator=(
    FileHandlerForTesting&&) noexcept = default;

FileHandlerForTesting::~FileHandlerForTesting() = default;

bool FileHandlerForTesting::CreateDefaultExistingPaths() const {
  return CreateRamoopsPath() && CreateSavePath() && CreatePreservePath() &&
         CreateRestorePath() && CreateChronosPath();
}

bool FileHandlerForTesting::CreateRestorePath() const {
  return base::CreateDirectory(GetFullPath(kDataRestorePath));
}

bool FileHandlerForTesting::CreateSavePath() const {
  return base::CreateDirectory(GetFullPath(kDataSavePath));
}

bool FileHandlerForTesting::CreatePreservePath() const {
  return base::CreateDirectory(GetFullPath(kPreservePath));
}

bool FileHandlerForTesting::CreateRamoopsPath() const {
  return base::CreateDirectory(GetFullPath(kRamoopsPath));
}

bool FileHandlerForTesting::CreateChronosPath() const {
  return base::CreateDirectory(GetFullPath(kChronosPath));
}

bool FileHandlerForTesting::HasDataSavedFlag() const {
  return base::PathExists(
      GetFullPath(kDataSavePath).Append(kDataSavedFileName));
}

bool FileHandlerForTesting::CreateOobeCompletedFlag() const {
  return base::WriteFile(
      GetFullPath(kChronosPath).Append(kOobeCompletedFileName), "");
}

bool FileHandlerForTesting::CreateMetricsReportingEnabledFile() const {
  return base::WriteFile(
      GetFullPath(kChronosPath).Append(kMetricsReportingEnabledFileName), "");
}

bool FileHandlerForTesting::RemoveMetricsReportingEnabledFile() const {
  return base::DeleteFile(
      GetFullPath(kChronosPath).Append(kMetricsReportingEnabledFileName));
}

bool FileHandlerForTesting::ReadPstoreData(std::string* data) const {
  return base::ReadFileToString(
      GetFullPath(kDataSavePath).Append(kPstoreFileName), data);
}

bool FileHandlerForTesting::WriteRamoopsData(const std::string& data) const {
  return base::WriteFile(GetFullPath(kRamoopsPath).Append(kRamoops0FileName),
                         data);
}

bool FileHandlerForTesting::RemoveRamoopsData() const {
  return base::DeleteFile(GetFullPath(kRamoopsPath).Append(kRamoops0FileName));
}

base::FilePath FileHandlerForTesting::GetFullPath(
    const std::string& path_without_root) const {
  return FileHandler::GetFullPath(path_without_root);
}

}  // namespace oobe_config
