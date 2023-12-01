// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_BLOB_UTIL_H_
#define LOGIN_MANAGER_BLOB_UTIL_H_

#include <stdint.h>

#include <string>
#include <vector>

#include <base/strings/string_piece.h>

namespace base {
class FilePath;
}

namespace google {
namespace protobuf {
class MessageLite;
}  // namespace protobuf
}  // namespace google

namespace login_manager {

// Another variation of Protobuf's SerializeAs family. Returns blob containing
// serialized data of the given |message|.
std::vector<uint8_t> SerializeAsBlob(
    const google::protobuf::MessageLite& message);

// Returns blob containing the same value of the given |str|.
std::vector<uint8_t> StringToBlob(base::StringPiece str);

// Returns string containing the same value of the given |blob|.
std::string BlobToString(const std::vector<uint8_t>& blob);

// Thin wrapper of base::WriteFile to adapt blob interface.
// Returns true on success.
bool WriteBlobToFile(const base::FilePath& filename,
                     const std::vector<uint8_t>& blob);

}  // namespace login_manager

#endif  // LOGIN_MANAGER_BLOB_UTIL_H_
