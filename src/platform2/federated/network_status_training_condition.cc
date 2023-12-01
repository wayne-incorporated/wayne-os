// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/variant_dictionary.h>
#include <dbus/bus.h>
#include <shill/dbus/client/client.h>
#include <memory>
#include <utility>

#include "federated/network_status_training_condition.h"

namespace federated {

NetworkStatusTrainingCondition::NetworkStatusTrainingCondition(
    std::unique_ptr<shill::Client> network_client)
    : dbus_network_client_(std::move(network_client)) {
  DVLOG(1) << "Construct NetworkStatusTrainingCondition";
}

// Check whether the network metered or not
bool NetworkStatusTrainingCondition::IsTrainingConditionSatisfied() const {
  auto service_properties = dbus_network_client_->GetDefaultServiceProperties();
  if (service_properties == nullptr ||
      service_properties->find(shill::kMeteredProperty) ==
          service_properties->end()) {
    // TODO(b/229921446): Make a new metric
    return false;
  }

  auto is_metered = brillo::GetVariantValueOrDefault<bool>(
      *service_properties, shill::kMeteredProperty);
  DVLOG(1) << "NetworkStatusTrainingCondition::IsTrainingConditionSatisfied: "
           << !is_metered;

  return !is_metered;
}

}  // namespace federated
