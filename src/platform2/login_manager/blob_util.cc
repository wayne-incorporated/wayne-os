// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/blob_util.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <google/protobuf/message_lite.h>

namespace login_manager {

std::vector<uint8_t> SerializeAsBlob(
    const google::protobuf::MessageLite& message) {
  std::vector<uint8_t> result;
  result.resize(message.ByteSizeLong());
  CHECK(message.SerializeToArray(result.data(), result.size()))
      << "Failed to serialize protobuf.";
  return result;
}

std::vector<uint8_t> StringToBlob(base::StringPiece str) {
  return std::vector<uint8_t>(str.begin(), str.end());
}

std::string BlobToString(const std::vector<uint8_t>& blob) {
  return std::string(reinterpret_cast<const char*>(blob.data()), blob.size());
}

bool WriteBlobToFile(const base::FilePath& filename,
                     const std::vector<uint8_t>& blob) {
  int result = base::WriteFile(
      filename, reinterpret_cast<const char*>(blob.data()), blob.size());
  return result >= 0 && static_cast<size_t>(result) == blob.size();
}

}  // namespace login_manager
