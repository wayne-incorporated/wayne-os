// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_FILE_UTILS_H_
#define RUNTIME_PROBE_UTILS_FILE_UTILS_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>
#include <base/values.h>

namespace runtime_probe {
namespace internal {

bool ReadFileToDict(const base::FilePath& dir_path,
                    base::StringPiece key,
                    bool log_error,
                    base::Value& result);
bool ReadFileToDict(const base::FilePath& dir_path,
                    const std::pair<base::StringPiece, base::StringPiece>& key,
                    bool log_error,
                    base::Value& result);

}  // namespace internal

bool ReadAndTrimFileToString(const base::FilePath& file_path, std::string& out);

// Maps files listed in |keys| and |optional_keys| under |dir_path| into key
// value pairs.
//
// The containers could be a set or a map. For set (or vector), each element is
// the filename. For map (or vector of key-value pairs), the value is the
// filename.
//
// |keys| represents the set of must have, if any |keys| is missed in the
// |dir_path|, an empty dictionary will be returned.
template <typename KeyContainerType, typename OptionalKeyContainerType>
std::optional<base::Value> MapFilesToDict(
    const base::FilePath& dir_path,
    const KeyContainerType& keys,
    const OptionalKeyContainerType& optional_keys) {
  base::Value result(base::Value::Type::DICT);

  for (const auto& key : keys) {
    if (!internal::ReadFileToDict(dir_path, key, true, result))
      return std::nullopt;
  }
  for (const auto& key : optional_keys) {
    internal::ReadFileToDict(dir_path, key, false, result);
  }
  return result;
}

// Same as above but without |optional_keys|.
template <typename KeyContainerType>
std::optional<base::Value> MapFilesToDict(const base::FilePath& dir_path,
                                          const KeyContainerType& keys) {
  return MapFilesToDict(dir_path, keys, std::vector<std::string>{});
}

// Returns list of files which match the pattern. The pattern can contains unix
// path wildcard. For example: "/a/*/b/*.txt". The path without wildcard only
// matches itself, for example: "/a/b/" => ["/a/b"].
std::vector<base::FilePath> Glob(const base::FilePath& pattern);
std::vector<base::FilePath> Glob(const std::string& pattern);

// Gets the path under the root directory provided by the `Context`. The path
// should be absolute.
base::FilePath GetRootedPath(const base::FilePath& path);
base::FilePath GetRootedPath(base::StringPiece path);

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_FILE_UTILS_H_
