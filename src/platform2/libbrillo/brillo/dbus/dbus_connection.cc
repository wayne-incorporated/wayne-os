// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/dbus/dbus_connection.h>

#include <base/logging.h>

namespace {
constexpr base::TimeDelta kDbusConnectWaitTime = base::Milliseconds(100);
}  // namespace

namespace brillo {

DBusConnection::DBusConnection() {}

DBusConnection::~DBusConnection() {
  if (bus_)
    bus_->ShutdownAndBlock();
}

scoped_refptr<dbus::Bus> DBusConnection::Connect() {
  return ConnectWithTimeout(base::TimeDelta());
}

scoped_refptr<dbus::Bus> DBusConnection::ConnectWithTimeout(
    base::TimeDelta timeout) {
  if (bus_)
    return bus_;

  base::TimeTicks deadline = base::TimeTicks::Now() + timeout;

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);

  do {
    if (bus->Connect()) {
      bus_ = bus;
      return bus_;
    }
    // Wait a bit to prevent trashing the device while waiting for the
    // dbus-daemon to start. Balance this with making sure we don't wait too
    // long and introduce unnecessary latency to the caller.
    base::PlatformThread::Sleep(kDbusConnectWaitTime);
  } while (base::TimeTicks::Now() < deadline);

  LOG(ERROR) << "Failed to get system bus after " << timeout.InSeconds()
             << " seconds.";
  return nullptr;
}

}  // namespace brillo
