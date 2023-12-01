// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/tools/battery_saver/battery_saver_mode_watcher.h"

#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/logging.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>

#include "power_manager/tools/battery_saver/proto_util.h"
#include "power_manager/tools/battery_saver/task_util.h"

namespace power_manager {

using ::org::chromium::PowerManagerProxyInterface;

BatterySaverModeWatcher::BatterySaverModeWatcher(
    PowerManagerProxyInterface& power_manager_proxy,
    StateChangedCallback callback)
    : power_manager_(&power_manager_proxy),
      callback_(std::move(callback)),
      weak_ptr_factory_(this) {
  power_manager_->RegisterBatterySaverModeStateChangedSignalHandler(
      base::BindRepeating(&BatterySaverModeWatcher::OnGotStateChangedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&BatterySaverModeWatcher::OnConnected,
                     weak_ptr_factory_.GetWeakPtr()));
}

void BatterySaverModeWatcher::OnConnected(const std::string& interface_name,
                                          const std::string& signal_name,
                                          bool success) {
  // If we failed to connect, issue an error.
  if (!success) {
    PostToCurrentSequence(base::BindOnce(
        callback_, absl::UnknownError("Failed to subscribe to D-Bus "
                                      "BatterySaverModeStateChanged signal.")));
    callback_.Reset();
    return;
  }

  // Now that we have subscribed, fetch the pre-existing state so that we can
  // send an initial update to the caller.
  //
  // We need to perform this query _after_ we subscribe to avoid a potential
  // race where the BSM state changes between our initial request and us
  // subscribing to the signal.
  //
  // The opposite race --- where we get a signal prior to us making a call to
  // `GetBatterySaverModeState` --- is also possible, but benign: it will result
  // in an additional callback of the current state.
  power_manager_->GetBatterySaverModeStateAsync(
      base::BindOnce(&BatterySaverModeWatcher::OnGotStateChangedSignal,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce([](brillo::Error* error) {
        // We failed to get an initial state. This may be because powerd hasn't
        // started up yet, or took too long to reply.
        //
        // We log the error, but continue to keep our signal subscription open
        // so that if, for example, powerd starts late, we'll still get BSM
        // updates.
        LOG(WARNING)
            << "Failed to fetch initial Battery Saver Mode state from D-Bus: "
            << error->GetMessage();
      }));
}

void BatterySaverModeWatcher::OnGotStateChangedSignal(
    const std::vector<uint8_t>& data) {
  // Deserialize the proto argument.
  std::optional<BatterySaverModeState> state =
      DeserializeProto<BatterySaverModeState>(data);
  if (!state.has_value()) {
    // Log and ignore.
    LOG(WARNING) << "Received invalid BatterySaverModeState data from "
                    "powerd via D-Bus. Ignoring.";
    return;
  }

  // Trigger our user's callback.
  PostToCurrentSequence(base::BindOnce(callback_, std::move(*state)));
}

}  // namespace power_manager
