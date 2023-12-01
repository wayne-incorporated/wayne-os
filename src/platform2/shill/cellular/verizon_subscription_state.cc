// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/verizon_subscription_state.h"

#include <vector>

namespace shill {

bool FindVerizonSubscriptionStateFromPco(
    const CellularPco& pco, SubscriptionState* subscription_state) {
  // Expected format:
  //       ID: FF 00
  //   Length: 04
  //     Data: 13 01 84 <x>
  //
  // where <x> can be:
  //    00: provisioned
  //    03: out of data credits
  //    05: unprovisioned

  const CellularPco::Element* element = pco.FindElement(0xFF00);
  if (!element)
    return false;

  const std::vector<uint8_t>& pco_data = element->data;
  if (pco_data.size() != 4 || pco_data[0] != 0x13 || pco_data[1] != 0x01 ||
      pco_data[2] != 0x84) {
    return false;
  }

  switch (pco_data[3]) {
    case 0x00:
      *subscription_state = SubscriptionState::kProvisioned;
      break;
    case 0x03:
      *subscription_state = SubscriptionState::kOutOfCredits;
      break;
    case 0x05:
      *subscription_state = SubscriptionState::kUnprovisioned;
      break;
    default:
      *subscription_state = SubscriptionState::kUnknown;
      break;
  }
  return true;
}

}  // namespace shill
