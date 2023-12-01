// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_UPDATER_UPDATE_STATUS_H_
#define BIOD_UPDATER_UPDATE_STATUS_H_

namespace biod {
namespace updater {

enum class UpdateStatus {
  kUpdateNotNecessary,
  kUpdateSucceeded,
  kUpdateFailedGetVersion,
  kUpdateFailedFlashProtect,
  kUpdateFailedRO,
  kUpdateFailedRW,
  kUpdateSucceededNeedPowerReset,
};

}  // namespace updater
}  // namespace biod

#endif  // BIOD_UPDATER_UPDATE_STATUS_H_
