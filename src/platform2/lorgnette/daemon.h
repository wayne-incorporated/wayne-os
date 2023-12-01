// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_DAEMON_H_
#define LORGNETTE_DAEMON_H_

#include <memory>

#include <base/cancelable_callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <brillo/daemons/dbus_daemon.h>

#include "lorgnette/dbus_service_adaptor.h"
#include "lorgnette/device_tracker.h"
#include "lorgnette/manager.h"

namespace lorgnette {

class LibusbWrapper;
class SaneClient;

class Daemon : public brillo::DBusServiceDaemon {
 public:
  // User and group to run the lorgnette process.
  static const char kScanGroupName[];
  static const char kScanUserName[];

  explicit Daemon(base::OnceClosure startup_callback);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() override;

  // Daemon will automatically shutdown after this length of idle time.
  static constexpr base::TimeDelta kNormalShutdownTimeout = base::Seconds(2);

  // A longer shutdown timeout that can be requested during slow operations.
  static constexpr base::TimeDelta kExtendedShutdownTimeout = base::Minutes(5);

 protected:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  void OnShutdown(int* return_code) override;

 private:
  friend class DaemonTest;

  // Restarts a timer for the termination of the daemon process.
  void PostponeShutdown(base::TimeDelta delay);
  void OnTimeout();
  void OnDebugChanged();

  std::unique_ptr<DBusServiceAdaptor> dbus_service_;
  base::OnceClosure startup_callback_;
  base::CancelableOnceClosure shutdown_callback_;

  std::unique_ptr<SaneClient> sane_client_;
  std::unique_ptr<LibusbWrapper> libusb_;
  std::unique_ptr<DeviceTracker> device_tracker_;

  // Keep as the last member variable.
  base::WeakPtrFactory<Daemon> weak_factory_{this};
};

}  // namespace lorgnette

#endif  // LORGNETTE_DAEMON_H_
