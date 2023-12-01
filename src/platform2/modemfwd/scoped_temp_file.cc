// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/scoped_temp_file.h"

#include <utility>

#include <base/files/file_util.h>

namespace modemfwd {

// static
std::unique_ptr<ScopedTempFile> ScopedTempFile::Create() {
  base::FilePath path;
  if (!base::CreateTemporaryFile(&path))
    return nullptr;

  return std::unique_ptr<ScopedTempFile>(new ScopedTempFile(path));
}

ScopedTempFile::ScopedTempFile(const base::FilePath& path) : path_(path) {}

ScopedTempFile::~ScopedTempFile() {
  base::DeleteFile(path_);
}

}  // namespace modemfwd
