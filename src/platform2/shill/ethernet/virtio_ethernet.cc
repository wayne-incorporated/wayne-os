// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/virtio_ethernet.h"

#include <unistd.h>
#include <utility>

#include "shill/control_interface.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/manager.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kEthernet;
static std::string ObjectID(const VirtioEthernet* v) {
  return v->GetRpcIdentifier().value();
}
}  // namespace Logging

VirtioEthernet::VirtioEthernet(Manager* manager,
                               const std::string& link_name,
                               const std::string& address,
                               int interface_index)
    : Ethernet(manager, link_name, address, interface_index) {
  SLOG(this, 2) << "VirtioEthernet device " << link_name << " initialized.";
}

VirtioEthernet::~VirtioEthernet() {
  // Nothing to be done beyond what Ethernet dtor does.
}

void VirtioEthernet::Start(EnabledStateChangedCallback callback) {
  // We are sometimes instantiated (by DeviceInfo) before the Linux kernel
  // has completed the setup function for the device (virtio_net:virtnet_probe).
  //
  // Furthermore, setting the IFF_UP flag on the device (as done in
  // Ethernet::Start) may cause the kernel IPv6 code to send packets even
  // though virtnet_probe has not completed.
  //
  // When that happens, the device gets stuck in a state where it cannot
  // transmit any frames. (See crbug.com/212041)
  //
  // To avoid this, we sleep to let the device setup function complete.
  SLOG(this, 2) << "Sleeping to let virtio initialize.";
  sleep(2);
  SLOG(this, 2) << "Starting virtio Ethernet.";
  Ethernet::Start(std::move(callback));
}

}  // namespace shill
