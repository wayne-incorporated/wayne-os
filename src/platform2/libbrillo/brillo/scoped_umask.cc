// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/scoped_umask.h"

#include <sys/stat.h>

namespace brillo {

ScopedUmask::ScopedUmask(mode_t new_umask) {
  saved_umask_ = umask(new_umask);
}

ScopedUmask::~ScopedUmask() {
  umask(saved_umask_);
}

}  // namespace brillo
