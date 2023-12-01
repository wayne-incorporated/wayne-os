// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_BUS_UTILS_H_
#define RUNTIME_PROBE_UTILS_BUS_UTILS_H_

#include <optional>

#include <base/files/file_path.h>
#include <base/values.h>

namespace runtime_probe {

// Probes the bus info from a sysfs device path. This is designed for the
// sysfs subsystem /sys/class/*. For example: /sys/class/net/eth0. This function
// probes the sysfs subsystem /sys/bus/* which is linked to
// `{node_path}/device`. The return values depend on the bus type. This supports
// pci, usb and sdio.
std::optional<base::Value> GetDeviceBusDataFromSysfsNode(
    const base::FilePath& node_path);

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_BUS_UTILS_H_
