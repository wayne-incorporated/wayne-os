// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/mojo_utils.h"

#include <utility>

#include <base/files/platform_file.h>
#include <base/logging.h>

namespace diagnostics::mojo_utils {

base::ScopedPlatformFile UnwrapMojoHandle(mojo::ScopedHandle handle) {
  base::ScopedPlatformFile fd;
  MojoResult mojo_result = mojo::UnwrapPlatformFile(std::move(handle), &fd);
  if (mojo_result != MOJO_RESULT_OK) {
    LOG(ERROR) << "Failed to unwrap handle: " << mojo_result;
    return base::ScopedPlatformFile();
  }
  return fd;
}

}  // namespace diagnostics::mojo_utils
