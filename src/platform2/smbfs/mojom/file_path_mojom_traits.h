// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_MOJOM_FILE_PATH_MOJOM_TRAITS_H_
#define SMBFS_MOJOM_FILE_PATH_MOJOM_TRAITS_H_

#include <string>

#include <base/files/file_path.h>

#include "smbfs/mojom/smbfs.mojom.h"

namespace mojo {

template <>
struct StructTraits<smbfs::mojom::FilePathDataView, base::FilePath> {
  static std::string path(const base::FilePath& path) { return path.value(); }

  static bool Read(smbfs::mojom::FilePathDataView data, base::FilePath* out) {
    std::string path;
    if (!data.ReadPath(&path)) {
      return false;
    }

    base::FilePath file_path(path);
    // Ensure what was deserialised matches what was provided.
    if (path.compare(file_path.value()) != 0) {
      return false;
    }

    if (!file_path.IsAbsolute() || file_path.ReferencesParent() ||
        file_path.EndsWithSeparator()) {
      return false;
    }

    *out = file_path;
    return true;
  }
};

}  // namespace mojo

#endif  // SMBFS_MOJOM_FILE_PATH_MOJOM_TRAITS_H_
