// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/mock_dhcp_controller.h"

#include "shill/technology.h"

namespace shill {

MockDHCPController::MockDHCPController(ControlInterface* control_interface,
                                       const std::string& device_name)
    : DHCPController(control_interface,
                     /*dispatcher=*/nullptr,
                     /*provider=*/nullptr,
                     device_name,
                     /*lease_file_suffix=*/"",
                     /*arp_gateway=*/false,
                     /*enable_rfc_8925=*/false,
                     /*hostname=*/"",
                     Technology::kUnknown,
                     /*metrics=*/nullptr) {}

MockDHCPController::~MockDHCPController() = default;

void MockDHCPController::RegisterCallbacks(UpdateCallback update_callback,
                                           DropCallback drop_callback) {
  update_callback_ = update_callback;
  drop_callback_ = drop_callback;
}

void MockDHCPController::TriggerUpdateCallback(
    const IPConfig::Properties& props) {
  update_callback_.Run(props, /*new_lease_acquired=*/true);
}

void MockDHCPController::TriggerDropCallback(bool is_voluntary) {
  drop_callback_.Run(is_voluntary);
}

void MockDHCPController::ProcessEventSignal(
    ClientEventReason reason, const KeyValueStore& configuration) {}
}  // namespace shill
