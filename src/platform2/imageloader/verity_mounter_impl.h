// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGELOADER_VERITY_MOUNTER_IMPL_H_
#define IMAGELOADER_VERITY_MOUNTER_IMPL_H_

#include <cstdint>
#include <string>

#include <base/files/file_path.h>

namespace imageloader {

// Parses a mapper table entry for a device denoted by "name" to determine the
// loop device number.
// Returns true on success.
bool MapperParametersToLoop(const std::string& verity_mount_parameters,
                            int32_t* loop);

// Returns true if an ancestor-descendant relationship holds for the given
// paths.
bool IsAncestor(const base::FilePath& ancenstor,
                const base::FilePath& descendant);

}  // namespace imageloader

#endif  // IMAGELOADER_VERITY_MOUNTER_IMPL_H_
