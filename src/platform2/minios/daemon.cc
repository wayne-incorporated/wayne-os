// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/daemon.h"

#include <utility>

#include <base/check.h>
#include <brillo/message_loops/message_loop.h>
#include <dbus/minios/dbus-constants.h>
#include <sysexits.h>

#include "minios/network_manager.h"
#include "minios/shill_proxy.h"
#include "minios/update_engine_proxy.h"

namespace minios {

Daemon::Daemon() : DBusServiceDaemon(kMiniOsServiceName) {}

void Daemon::Start() {
  mini_os_->SetStateReporter(dbus_adaptor_.get());
  mini_os_->Run();
}

int Daemon::OnEventLoopStarted() {
  int return_code = brillo::DBusServiceDaemon::OnEventLoopStarted();
  if (return_code != EX_OK)
    return return_code;

  brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::BindOnce(&Daemon::Start, base::Unretained(this)));
  return EX_OK;
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr, bus_, org::chromium::MiniOsInterfaceAdaptor::GetObjectPath());

  bus_for_proxies_ = dbus_connection_for_proxies_.Connect();
  CHECK(bus_for_proxies_);

  std::shared_ptr<NetworkManagerInterface> network_manager =
      std::make_shared<NetworkManager>(
          std::make_unique<ShillProxy>(bus_for_proxies_));

  mini_os_ = std::make_shared<MiniOs>(
      std::make_shared<UpdateEngineProxy>(
          std::make_unique<org::chromium::UpdateEngineInterfaceProxy>(
              bus_for_proxies_)),
      network_manager);

  dbus_adaptor_ = std::make_unique<DBusAdaptor>(
      std::make_unique<DBusService>(mini_os_, network_manager));

  dbus_adaptor_->RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed.", true));
}

}  // namespace minios
