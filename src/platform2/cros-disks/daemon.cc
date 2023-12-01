// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/daemon.h"

#include <base/check.h>
#include <chromeos/dbus/service_constants.h>

namespace cros_disks {

Daemon::Daemon(bool has_session_manager)
    : brillo::DBusServiceDaemon(kCrosDisksServiceName),
      has_session_manager_(has_session_manager) {
  process_reaper_.Register(this);
  CHECK(platform_.SetMountUser("chronos"));
  CHECK(archive_manager_.Initialize());
  CHECK(disk_manager_.Initialize());
  CHECK(fuse_manager_.Initialize());
}

Daemon::~Daemon() = default;

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  server_ = std::make_unique<CrosDisksServer>(
      bus_, &platform_, &disk_monitor_, &format_manager_, &partition_manager_,
      &rename_manager_);

  // Register mount managers with the commonly used ones come first.
  server_->RegisterMountManager(&disk_manager_);
  server_->RegisterMountManager(&archive_manager_);
  server_->RegisterMountManager(&fuse_manager_);

  event_moderator_ = std::make_unique<DeviceEventModerator>(
      server_.get(), &disk_monitor_, has_session_manager_);

  if (has_session_manager_) {
    session_manager_proxy_ = std::make_unique<SessionManagerProxy>(bus_);
    session_manager_proxy_->AddObserver(server_.get());
    session_manager_proxy_->AddObserver(event_moderator_.get());
  }

  device_event_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      disk_monitor_.udev_monitor_fd(),
      base::BindRepeating(&DeviceEventModerator::ProcessDeviceEvents,
                          base::Unretained(event_moderator_.get())));

  server_->RegisterAsync(
      sequencer->GetHandler("Failed to export cros-disks service.", false));
}

}  // namespace cros_disks
