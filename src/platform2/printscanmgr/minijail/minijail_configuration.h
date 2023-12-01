// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_MINIJAIL_MINIJAIL_CONFIGURATION_H_
#define PRINTSCANMGR_MINIJAIL_MINIJAIL_CONFIGURATION_H_

namespace printscanmgr {

// Configures printscanmgr's minijail, then enters it. Any errors encountered
// during configuration result in a CHECK, and the daemon will crash rather than
// start without a sandbox.
void EnterDaemonMinijail();

// Enters a new mount namespace for the executor. We don't want anyone other
// than our descendants to see our tmpfs.
void EnterExecutorMinijail();

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_MINIJAIL_MINIJAIL_CONFIGURATION_H_
