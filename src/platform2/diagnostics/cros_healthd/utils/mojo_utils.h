// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_UTILS_H_

#include <mojo/public/cpp/system/platform_handle.h>

namespace diagnostics::mojo_utils {

// Converts a |mojo::ScopedHandle| into a |base::ScopedPlatformFile| which can
// be read as a file descriptor. Returns empty |base::ScopedPlatformFile| if
// error happened.
base::ScopedPlatformFile UnwrapMojoHandle(mojo::ScopedHandle handle);

}  // namespace diagnostics::mojo_utils

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_UTILS_H_
