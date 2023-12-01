// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/rollback_info_command.h"

namespace ec {

int32_t RollbackInfoCommand::ID() const {
  return Resp()->id;
}

int32_t RollbackInfoCommand::MinVersion() const {
  return Resp()->rollback_min_version;
}

int32_t RollbackInfoCommand::RWVersion() const {
  return Resp()->rw_rollback_version;
}

}  // namespace ec
