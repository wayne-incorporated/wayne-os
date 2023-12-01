// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_UPDATER_UPDATE_REASON_H_
#define BIOD_UPDATER_UPDATE_REASON_H_

#include <brillo/enum_flags.h>

namespace biod {
namespace updater {

// The following UpdateReason values are used for reporting
// metrics (UMA). Do not change their values without
// considering the impact to pre-reported metrics.
//  None                                         = 0,
//  Mismatch RW Version                          = 1,
//  Mismatch RO Version                          = 2,
//  Mismatch RW and RO Version                   = 3,
//  Active Image RO                              = 4,
//  Mismatch RW Version        + Active Image RO = 5,
//  Mismatch RO Version        + Active Image RO = 6,
//  Mismatch RW and RO Version + Active Image RO = 7,
enum class UpdateReason : int {
  kNone = 0,
  kMismatchRWVersion = 1 << 0,
  kMismatchROVersion = 1 << 1,
  kActiveImageRO = 1 << 2,

  kMaxValue = kMismatchRWVersion | kMismatchROVersion | kActiveImageRO,
};

DECLARE_FLAGS_ENUM(UpdateReason);

}  // namespace updater
}  // namespace biod

#endif  // BIOD_UPDATER_UPDATE_REASON_H_
