// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/opencl_caching/utils.h"

#include <string>

#include <base/files/dir_reader_posix.h>
#include <base/files/file_util.h>

#include "ml_core/opencl_caching/constants.h"

namespace {
const char kPrebuiltCacheDir[] = "cl_cache";
}  // namespace

namespace cros {

base::FilePath PrebuiltCacheDir(const base::FilePath& dlc_root_path) {
  return dlc_root_path.Append(kPrebuiltCacheDir);
}

bool DirIsEmpty(const base::FilePath& source_dir) {
  bool is_empty = true;

  base::DirReaderPosix reader(kOpenCLCachingDir);
  if (!reader.IsValid()) {
    LOG(ERROR) << "Error opening cache directory";
    return is_empty;
  }

  while (reader.Next()) {
    // Don't count ".", ".."
    if (reader.name() == std::string(base::FilePath::kCurrentDirectory) ||
        reader.name() == std::string(base::FilePath::kParentDirectory)) {
      continue;
    }
    is_empty = false;
    break;
  }

  return is_empty;
}

// Deletes all the files in the cache
void ClearCacheDirectory() {
  base::DirReaderPosix reader(kOpenCLCachingDir);
  if (!reader.IsValid()) {
    LOG(ERROR) << "Error opening cache directory";
    return;
  }

  while (reader.Next()) {
    // Don't delete ".", ".."
    if (reader.name() == std::string(base::FilePath::kCurrentDirectory) ||
        reader.name() == std::string(base::FilePath::kParentDirectory)) {
      continue;
    }

    auto to_delete = base::FilePath(kOpenCLCachingDir).Append(reader.name());
    if (!base::DeleteFile(to_delete)) {
      LOG(ERROR) << "Error deleting " << to_delete;
    }
  }
}

// Will copy cache files from the source_dir into kOpenCLCachingDir.
// It will overwrite any existing files of the same name.
void CopyCacheFiles(const base::FilePath& source_dir) {
  base::DirReaderPosix reader(source_dir.value().c_str());
  if (!reader.IsValid()) {
    LOG(ERROR) << "Error opening source directory";
    return;
  }

  while (reader.Next()) {
    auto source = source_dir.Append(reader.name());

    // Skip ".", ".." and symlinks
    if (reader.name() == std::string(base::FilePath::kCurrentDirectory) ||
        reader.name() == std::string(base::FilePath::kParentDirectory) ||
        base::IsLink(source)) {
      continue;
    }

    auto target = base::FilePath(kOpenCLCachingDir).Append(reader.name());
    LOG(INFO) << "Copying " << source << " to OpenCL cache dir";
    if (!base::CopyFile(source, target)) {
      LOG(ERROR) << "Error copying " << source << " to " << target;
    }
  }
}

}  // namespace cros
