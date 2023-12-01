// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_BASE_FILE_UTILS_H_
#define DIAGNOSTICS_BASE_FILE_UTILS_H_

#include <optional>
#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_piece.h>
#include <brillo/brillo_export.h>

namespace diagnostics {

// Returns the root dir. This can be the overridden during unit tests.
base::FilePath GetRootDir();
// Returns the paths under the root dir. This does nothing in real
// implementations. The root directory can be overridden in unit tests. Note
// that the path must be absolute.
base::FilePath GetRootedPath(base::FilePath path);
// Just like the above but turns a base::StringPiece into base::FilePath.
inline base::FilePath GetRootedPath(base::StringPiece path) {
  return GetRootedPath(base::FilePath{path});
}

#ifndef USE_TEST
static_assert(false,
              "USE_TEST is not defined. Did you set right gn dependency?");
#elif USE_TEST == false
// These real implementations are short. Just inline them in the header.
inline base::FilePath GetRootDir() {
  return base::FilePath{"/"};
}
inline base::FilePath GetRootedPath(base::FilePath path) {
  return path;
}
#endif

// Reads the contents of |file_path| into |out|, trims leading and trailing
// whitespace. Returns true on success.
// |StringType| can be any type which can be converted from |std::string|.
// For example, |std::optional<std::string>|.
template <typename StringType>
bool ReadAndTrimString(const base::FilePath& file_path, StringType* out) {
  DCHECK(out);
  std::string out_raw;

  if (!ReadAndTrimString(file_path, &out_raw))
    return false;

  *out = static_cast<StringType>(out_raw);
  return true;
}

template <>
BRILLO_EXPORT bool ReadAndTrimString<std::string>(
    const base::FilePath& file_path, std::string* out);

// Like ReadAndTrimString() above, but expects a |filename| within |directory|
// to be read.
template <typename StringType>
bool ReadAndTrimString(const base::FilePath& directory,
                       const std::string& filename,
                       StringType* out) {
  return ReadAndTrimString(directory.Append(filename), out);
}

// Reads an integer value from a file and converts it using the provided
// function. Returns true on success.
template <typename T>
bool ReadInteger(const base::FilePath& file_path,
                 bool (*StringToInteger)(base::StringPiece, T*),
                 T* out) {
  DCHECK(StringToInteger);
  DCHECK(out);

  std::string buffer;
  if (!ReadAndTrimString(file_path, &buffer))
    return false;

  return StringToInteger(buffer, out);
}

// Like ReadInteger() above, but expects a |filename| within |directory| to be
// read.
template <typename T>
bool ReadInteger(const base::FilePath& directory,
                 const std::string& filename,
                 bool (*StringToInteger)(base::StringPiece, T*),
                 T* out) {
  return ReadInteger(directory.AppendASCII(filename), StringToInteger, out);
}

}  // namespace diagnostics

#endif  // DIAGNOSTICS_BASE_FILE_UTILS_H_
