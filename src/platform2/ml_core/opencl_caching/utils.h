// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_CORE_OPENCL_CACHING_UTILS_H_
#define ML_CORE_OPENCL_CACHING_UTILS_H_

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace cros {

// Used in camera stack, so export them.
BRILLO_EXPORT base::FilePath PrebuiltCacheDir(
    const base::FilePath& dlc_root_path);
BRILLO_EXPORT bool DirIsEmpty(const base::FilePath& source_dir);

// Only used in opencl_cacher, no need to export
void ClearCacheDirectory();
void CopyCacheFiles(const base::FilePath& source_dir);

}  // namespace cros

#endif  // ML_CORE_OPENCL_CACHING_UTILS_H_
