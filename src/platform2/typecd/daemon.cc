// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include "typecd/daemon.h"

#include <base/check.h>
#include <base/logging.h>
#include <dbus/debugd/dbus-constants.h>
#include <dbus/typecd/dbus-constants.h>

#include "typecd/cros_config_util.h"

namespace {
const char kObjectServicePath[] = "/org/chromium/typecd/ObjectManager";
}  // namespace

namespace typecd {

Daemon::Daemon()
    : DBusServiceDaemon(kTypecdServiceName, kObjectServicePath),
      udev_monitor_(new UdevMonitor()),
      port_manager_(new PortManager()),
      weak_factory_(this) {}

Daemon::~Daemon() {}

int Daemon::OnInit() {
  int exit_code = DBusServiceDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  LOG(INFO) << "Daemon started.";
  if (!udev_monitor_->InitUdev()) {
    LOG(ERROR) << "udev init failed.";
    return -1;
  }

  // Set the metrics reporting class.
  port_manager_->SetMetrics(&metrics_);

  // Register the session_manager proxy.
  session_manager_proxy_ = std::make_unique<SessionManagerProxy>(bus_);

  cros_ec_util_ = std::make_unique<CrosECUtil>(bus_);
  port_manager_->SetECUtil(cros_ec_util_.get());

  port_manager_->SetDBusManager(dbus_mgr_.get());
  dbus_mgr_->SetPortManager(port_manager_.get());

  features_client_ = std::make_unique<ChromeFeaturesServiceClient>(bus_);
  features_client_->FetchPeripheralDataAccessEnabled();
  port_manager_->SetFeaturesClient(features_client_.get());
  dbus_mgr_->SetFeaturesClient(features_client_.get());

  // Stash whether mode entry is supported at init, instead of querying it
  // repeatedly. But, add a listener for debugd service changes. In some cases
  // typecd will init before debugd causing this initial check for mode entry
  // to fail where mode entry will be supported once debugd initializes.
  bool mode_entry_supported = cros_ec_util_->ModeEntrySupported();
  if (!mode_entry_supported) {
    LOG(INFO) << "Mode entry currently not supported on this device.";
    bus_->ListenForServiceOwnerChange(
        debugd::kDebugdServiceName,
        base::BindRepeating(&Daemon::DebugdListener,
                            weak_factory_.GetWeakPtr()));
  }
  port_manager_->SetModeEntrySupported(mode_entry_supported);

  auto config = std::make_unique<CrosConfigUtil>();
  if (mode_entry_supported && config->APModeEntryDPOnly())
    port_manager_->SetSupportsUSB4(false);

  InitUserActiveState();
  session_manager_proxy_->AddObserver(port_manager_.get());

  // Add any observers to |udev_monitor_| here.
  udev_monitor_->AddTypecObserver(port_manager_.get());

  udev_monitor_->ScanDevices();
  udev_monitor_->BeginMonitoring();

  return 0;
}

void Daemon::InitUserActiveState() {
  bool active = !session_manager_proxy_->IsScreenLocked() &&
                session_manager_proxy_->IsSessionStarted();

  port_manager_->SetUserActive(active);
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK(!dbus_object_);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      object_manager_.get(), bus_, dbus::ObjectPath(kTypecdServicePath));
  dbus_mgr_ = std::make_unique<DBusManager>(dbus_object_.get());

  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object", true /* failure_is_fatal */));
}

void Daemon::DebugdListener(const std::string& owner) {
  LOG(INFO) << "Update received from debugd (" << owner << ").";

  bool mode_entry_supported = cros_ec_util_->ModeEntrySupported();
  if (!mode_entry_supported)
    return;

  port_manager_->SetModeEntrySupported(mode_entry_supported);
  LOG(INFO) << "Mode entry now supported on this device.";
}

}  // namespace typecd
