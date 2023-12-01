// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/upstart/upstart.h"

#include "shill/control_interface.h"
#include "shill/upstart/upstart_proxy_interface.h"

namespace shill {

// static
const char Upstart::kShillDisconnectEvent[] = "shill-disconnected";
const char Upstart::kShillConnectEvent[] = "shill-connected";

Upstart::Upstart(ControlInterface* control_interface)
    : upstart_proxy_(control_interface->CreateUpstartProxy()) {}

Upstart::~Upstart() = default;

void Upstart::NotifyDisconnected() {
  upstart_proxy_->EmitEvent(kShillDisconnectEvent, {}, false);
}

void Upstart::NotifyConnected() {
  upstart_proxy_->EmitEvent(kShillConnectEvent, {}, false);
}

}  // namespace shill
