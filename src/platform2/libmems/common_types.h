// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_COMMON_TYPES_H_
#define LIBMEMS_COMMON_TYPES_H_

#include <linux/iio/types.h>
#include <optional>
#include <string>
#include <vector>

#include "libmems/export.h"

namespace libmems {

LIBMEMS_EXPORT uint64_t IioEventCode(iio_chan_type chan_type,
                                     iio_event_type event_type,
                                     iio_event_direction dir,
                                     int channel);

constexpr int kErrorBufferSize = 256;
constexpr int kReadAttrBufferSize = 256;

constexpr char kDeviceIdPrefix[] = "iio:device";
constexpr char kIioSysfsTrigger[] = "iio_sysfs_trigger";
constexpr char kTriggerIdPrefix[] = "trigger";

constexpr char kHrtimerNameFormatString[] = "iioservice-%i";

// The attribute name to get the device name with
// IioDevice::ReadStringAttribute.
constexpr char kDeviceName[] = "name";

constexpr char kFrequencyAttr[] = "frequency";
constexpr char kSamplingFrequencyAttr[] = "sampling_frequency";
constexpr char kHWFifoTimeoutAttr[] = "buffer/hwfifo_timeout";
constexpr char kSamplingFrequencyAvailable[] = "sampling_frequency_available";
constexpr char kLabelAttr[] = "label";
constexpr char kLocationAttr[] = "location";

constexpr double kFrequencyEpsilon = 0.001;  // Hz

constexpr char kRawAttr[] = "raw";
constexpr char kTimestampAttr[] = "timestamp";

constexpr char kSysDevString[] = "/sys/bus/iio/devices";
constexpr char kDevString[] = "/dev";

constexpr char kAccelName[] = "accel";
constexpr char kGyroName[] = "anglvel";
constexpr char kLightName[] = "illuminance";
constexpr char kProxName[] = "proximity";
constexpr char kSyncName[] = "count";
constexpr char kMagnName[] = "magn";
constexpr char kLidAngleName[] = "angl";
constexpr char kBaroName[] = "baro";
constexpr char kAccelUncalibName[] = "accel_uncalib";
constexpr char kGyroUncalibName[] = "anglvel_uncalib";
constexpr char kMagnUncalibName[] = "magn_uncalib";

LIBMEMS_EXPORT std::optional<std::string> GetIioSarSensorDevlink(
    const std::string& sys_path);

}  // namespace libmems

#endif  // LIBMEMS_COMMON_TYPES_H_
