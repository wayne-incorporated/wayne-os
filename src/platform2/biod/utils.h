// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_UTILS_H_
#define BIOD_UTILS_H_

#include <string>
#include <type_traits>

namespace biod {

/**
 * @brief Convert id to a privacy preserving identifier string.
 *
 * Log files are uploaded via crash reports and feedback reports.
 * This function helps ensure that the IDs logged are only unique within
 * a single crash/feedback report and not across many different reports.
 * Only use this string for logging purposes.
 *
 * @param id A plain text string id.
 * @return std::string The mutated loggable id string.
 */
std::string LogSafeID(const std::string& id);

/**
 * @brief Callback invoked when signal is connected
 *
 * This function is compatible with |on_connected_callback| argument
 * in ConnectToSignal() DBus method.
 *
 * @param interface_name Name of the interface which provides the signal.
 * @param signal_name Name of the signal we are connecting to.
 * @param success Indicates if connection was established.
 */
void LogOnSignalConnected(const std::string& interface_name,
                          const std::string& signal_name,
                          bool success);
}  // namespace biod

#endif  // BIOD_UTILS_H_
