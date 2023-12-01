// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_METRICS_UTILS_H_
#define SHILL_WIFI_WIFI_METRICS_UTILS_H_

#include <string>

#include "shill/bluetooth/bluetooth_manager_interface.h"
#include "shill/metrics.h"

namespace shill::WiFiMetricsUtils {

// Given a specific AP OUI, can the client add it to the reported metrics?
bool CanReportOUI(int oui);

// Can the client add the WiFi adapter to the reported metrics?
bool CanReportAdapterInfo(const Metrics::WiFiAdapterInfo& info);

// Used to report the bootID in WiFi structured metrics to detect events that
// belong to different boots.
std::string GetBootId();

// This is only used by tests. It returns an AP OUI that is in the allowlist of
// OUIs that can be reported. go/totw/135.
int AllowlistedOUIForTesting();

Metrics::BTProfileConnectionState ConvertBTProfileConnectionState(
    BluetoothManagerInterface::BTProfileConnectionState state);

}  // namespace shill::WiFiMetricsUtils

#endif  // SHILL_WIFI_WIFI_METRICS_UTILS_H_
