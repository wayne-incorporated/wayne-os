// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_FILES_SCOPED_DIR_H_
#define LIBBRILLO_BRILLO_FILES_SCOPED_DIR_H_

#include <dirent.h>

#include <base/scoped_generic.h>

#define HANDLE_EINTR_IF_EQ(x, val)                             \
  ({                                                           \
    decltype(x) eintr_wrapper_result;                          \
    do {                                                       \
      eintr_wrapper_result = (x);                              \
    } while (eintr_wrapper_result == (val) && errno == EINTR); \
    eintr_wrapper_result;                                      \
  })

namespace brillo {

struct ScopedDIRCloseTraits {
  static DIR* InvalidValue() { return nullptr; }
  static void Free(DIR* dir) {
    if (dir != nullptr) {
      closedir(dir);
    }
  }
};

typedef base::ScopedGeneric<DIR*, ScopedDIRCloseTraits> ScopedDIR;

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_FILES_SCOPED_DIR_H_
