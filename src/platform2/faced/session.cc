// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/session.h"

namespace faced {

uint64_t GenerateSessionId(absl::BitGen& bitgen) {
  return absl::Uniform<uint64_t>(bitgen);
}

}  // namespace faced
