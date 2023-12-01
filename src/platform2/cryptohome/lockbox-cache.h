// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_LOCKBOX_CACHE_H_
#define CRYPTOHOME_LOCKBOX_CACHE_H_

#include <base/files/file_path.h>
#include <base/logging.h>

#include "cryptohome/platform.h"

namespace cryptohome {

// Verify the lockbox contents at |lockbox_path| against the NVRAM space
// contents at |nvram_path| and write the lockbox contents to |cache_path| upon
// successful verification. Return value indicates verification status.
[[nodiscard]] bool CacheLockbox(Platform* platform,
                                const base::FilePath& nvram_path,
                                const base::FilePath& lockbox_path,
                                const base::FilePath& cache_path);

}  // namespace cryptohome

#endif  // CRYPTOHOME_LOCKBOX_CACHE_H_
