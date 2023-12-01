// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_MODE_WATCHER_H_
#define POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_MODE_WATCHER_H_

#include <string>
#include <vector>

#include <absl/status/statusor.h>
#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>
#include <power_manager-client/power_manager/dbus-proxies.h>

namespace power_manager {

// Watches for changes in the system's Battery Saver Mode (BSM) state.
//
// `powerd` manages the state of BSM, and sends a D-Bus signal whenever the
// state changes. This class subscribes to the signal and issues a callback
// each time the state changes. The initial BSM state is also queried, and
// a callback fired when fetched.
//
// All calls to this class must be on the same sequence.
class BatterySaverModeWatcher {
 public:
  using StateChangedCallback = base::RepeatingCallback<void(
      absl::StatusOr<BatterySaverModeState> new_state)>;

  // Create a BatterySaverModeWatcher using the given D-Bus proxy.
  //
  // The callback will be called once with the initial state of BSM, and then
  // each time a signal is received from `powerd` indicating the state of BSM
  // has changed.
  //
  // The callback receives a parameter of type
  // `absl::StatusOr<BatterySaverModeState`. An error value will only be
  // passed in in the case of a permanent failure. If there is a transient
  // failure (such as `powerd` not running when the watcher instance is
  // created), a warning will be logged, but the watcher will continue to wait
  // for future signals.
  //
  // `power_manager_proxy` must outlive the class instance.
  explicit BatterySaverModeWatcher(
      org::chromium::PowerManagerProxyInterface& power_manager_proxy,
      StateChangedCallback callback);

  // Disallow copy and move.
  BatterySaverModeWatcher(const BatterySaverModeWatcher&) = delete;
  BatterySaverModeWatcher& operator=(const BatterySaverModeWatcher&) = delete;

  ~BatterySaverModeWatcher() = default;

 private:
  // Called when BatterySaverModeWatcher has either successfully subscribed to
  // the BSM signal, or if the subscription failed.
  void OnConnected(const std::string& interface_name,
                   const std::string& signal_name,
                   bool success);

  // Called when we get a reply to our initial query about the BSM state.
  void OnGotInitialStateFailure(brillo::Error* error);

  // Called when we get a signal from powerd about a change in BSM state.
  void OnGotStateChangedSignal(const std::vector<uint8_t>& data);

  // PowerManager D-Bus interface. Owned elsewhere.
  org::chromium::PowerManagerProxyInterface* power_manager_;

  // User callback, called each time a BSM state is observed.
  StateChangedCallback callback_;

  // Must be last member in the class.
  base::WeakPtrFactory<BatterySaverModeWatcher> weak_ptr_factory_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_MODE_WATCHER_H_
