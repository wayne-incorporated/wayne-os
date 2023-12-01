// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_EC_CONSTANTS_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_EC_CONSTANTS_H_

#include <poll.h>

#include <cstdint>

namespace diagnostics {
namespace wilco {

// Folder path exposed by sysfs EC driver.
inline constexpr char kEcDriverSysfsPath[] =
    "sys/bus/platform/devices/GOOG000C:00/";

// Folder path to EC properties exposed by sysfs EC driver. Relative path to
// |kEcDriverSysfsPath|.
inline constexpr char kEcDriverSysfsPropertiesPath[] = "properties/";

// Max request and response payload size for EC telemetry command.
inline constexpr const int64_t kEcGetTelemetryPayloadMaxSize = 32;

// Devfs node exposed by EC driver to EC telemetry data.
inline constexpr char kEcGetTelemetryFilePath[] = "dev/wilco_telem0";

// EC event file path.
inline constexpr char kEcEventFilePath[] = "dev/wilco_event0";

// The driver is expected to populate the |kEcEventFilePath| file, therefore
// this constant holds the specific flag for use with poll().
inline constexpr int16_t kEcEventFilePollEvents = POLLIN;

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_EC_CONSTANTS_H_
