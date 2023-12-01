// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_TELEM_TELEM_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_TELEM_TELEM_H_

namespace diagnostics {

// 'telem' sub-command for cros-health-tool:
//
// Test driver for cros_healthd's telemetry collection. Supports requesting a
// single category at a time.
int telem_main(int argc, char** argv);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_TELEM_TELEM_H_
