// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_USER_H_
#define CROS_DISKS_USER_H_

#include <sys/types.h>

namespace cros_disks {

// UID of the chronos user running UI and user apps.
constexpr uid_t kChronosUID = 1000;
// GID of the chronos user running UI and user apps.
constexpr uid_t kChronosGID = 1000;

// GID of the chronos-access group used to broker access to user's files.
constexpr gid_t kChronosAccessGID = 1001;

// UID/GID of an user owning a file/process.
struct OwnerUser {
  uid_t uid;
  gid_t gid;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_USER_H_
