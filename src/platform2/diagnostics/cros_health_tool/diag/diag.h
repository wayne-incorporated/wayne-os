// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_H_

namespace diagnostics {

// 'diag' sub-command for cros-health-tool:
//
// Test driver for libdiag. Only supports running a single diagnostic routine
// at a time.
int diag_main(int argc, char** argv);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_H_
