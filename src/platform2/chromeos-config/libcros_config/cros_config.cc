// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Library to provide access to the Chrome OS model configuration

#include "chromeos-config/libcros_config/cros_config.h"

#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <brillo/file_utils.h>

namespace {
const char kConfigFSBasePath[] = "/run/chromeos-config/v1";
}  // namespace

namespace brillo {

CrosConfig::CrosConfig() {}

CrosConfig::~CrosConfig() {}

bool CrosConfig::GetString(const std::string& path,
                           const std::string& property,
                           std::string* val_out) {
  if (path.empty() || path[0] != '/') {
    CROS_CONFIG_LOG(ERROR) << "Path parameter must begin with \"/\".";
    return false;
  }

  auto filepath = base::FilePath(kConfigFSBasePath);
  for (const auto& part : base::SplitStringPiece(
           path, "/", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    filepath = filepath.Append(part);
  }
  filepath = filepath.Append(property);
  return base::ReadFileToString(filepath, val_out);
}

}  // namespace brillo
