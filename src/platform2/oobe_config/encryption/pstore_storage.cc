// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/encryption/pstore_storage.h"

#include <optional>
#include <sstream>
#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>

#include "oobe_config/filesystem/file_handler.h"

namespace oobe_config {
namespace {

const char kRollbackDataKey[] = "rollback_data";

bool ExtractRollbackData(const base::FilePath& file,
                         std::string* rollback_data) {
  std::string file_content;
  base::ReadFileToString(file, &file_content);
  std::stringstream file_stream(file_content);
  std::string key;
  while (file_stream && key != kRollbackDataKey) {
    file_stream >> key;
  }
  if (file_stream && key == kRollbackDataKey) {
    std::string hex_rollback_data;
    file_stream >> hex_rollback_data;
    *rollback_data = hex_rollback_data;
    return true;  // Data may be completely empty - that is valid as well.
  }
  return false;
}

std::optional<std::string> HexToBinary(const std::string& hex) {
  std::string binary;
  bool success = base::HexStringToString(hex, &binary);

  if (!success) {
    LOG(ERROR) << "Could not decode rollback data.";
    return std::nullopt;
  }
  return binary;
}

}  // namespace

bool StageForPstore(const std::string& data,
                    const oobe_config::FileHandler& file_handler) {
  std::string hex_data_with_header = base::StrCat(
      {kRollbackDataKey, " ", base::HexEncode(data.data(), data.size())});

  return file_handler.WritePstoreData(hex_data_with_header);
}

std::optional<std::string> LoadFromPstore(
    const oobe_config::FileHandler& file_handler) {
  base::FileEnumerator pmsg_ramoops_enumerator =
      file_handler.RamoopsFileEnumerator();
  for (base::FilePath ramoops_file = pmsg_ramoops_enumerator.Next();
       !ramoops_file.empty(); ramoops_file = pmsg_ramoops_enumerator.Next()) {
    LOG(INFO) << "Looking at file " << ramoops_file.value();
    std::string rollback_data;
    if (ExtractRollbackData(ramoops_file, &rollback_data)) {
      return HexToBinary(rollback_data);
    }
    LOG(INFO) << "No rollback data found in that file.";
  }
  LOG(ERROR) << "No rollback data found.";
  return std::nullopt;
}

}  // namespace oobe_config
