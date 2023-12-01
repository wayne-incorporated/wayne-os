// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_EVENT_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_EVENT_H_

namespace diagnostics {

// 'event' sub-command for cros-health-tool:
//
// Test driver for cros_healthd's event subscription. Supports subscribing to a
// single category of events at a time.
int event_main(int argc, char** argv);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_EVENT_H_
