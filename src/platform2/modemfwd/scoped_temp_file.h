// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_SCOPED_TEMP_FILE_H_
#define MODEMFWD_SCOPED_TEMP_FILE_H_

#include <memory>

#include <base/files/file_path.h>

namespace modemfwd {

class ScopedTempFile {
 public:
  static std::unique_ptr<ScopedTempFile> Create();

  ~ScopedTempFile();

  const base::FilePath& path() const { return path_; }

 private:
  explicit ScopedTempFile(const base::FilePath& path);
  ScopedTempFile(const ScopedTempFile&) = delete;
  ScopedTempFile& operator=(const ScopedTempFile&) = delete;

  const base::FilePath path_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_SCOPED_TEMP_FILE_H_
