// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_VERSION_H_
#define BIOD_BIOD_VERSION_H_

#include <base/logging.h>
#include <brillo/vcsid.h>

namespace biod {

static inline void LogVersion() {
  LOG(INFO) << "vcsid " << brillo::kShortVCSID.value_or("<UNSET>");
}

}  // namespace biod

#endif  // BIOD_BIOD_VERSION_H_
