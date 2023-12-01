// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_MINIJAIL_MINIJAIL_CONFIGURATION_H_
#define RMAD_MINIJAIL_MINIJAIL_CONFIGURATION_H_

namespace rmad {

// Configures minijail for the RMA daemon, then enters it.
void EnterMinijail(bool set_admin_caps);

// Enters a new mount namespace. We don't want anyone other than our descendants
// to see our tmpfs.
void NewMountNamespace();

}  // namespace rmad

#endif  // RMAD_MINIJAIL_MINIJAIL_CONFIGURATION_H_
