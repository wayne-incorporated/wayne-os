// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_mode_command.h"

namespace ec {

FpMode FpModeCommand::Mode() const {
  return FpMode(Resp()->mode);
}

}  // namespace ec
