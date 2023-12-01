// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_FILE_DECOMPRESSOR_H_
#define MODEMFWD_FILE_DECOMPRESSOR_H_

#include <base/files/file_path.h>

namespace modemfwd {

// Decompresses a XZ file at |in_file_path| into a file at |out_file_path|.
// Returns true on success.
bool DecompressXzFile(const base::FilePath& in_file_path,
                      const base::FilePath& out_file_path);

}  // namespace modemfwd

#endif  // MODEMFWD_FILE_DECOMPRESSOR_H_
