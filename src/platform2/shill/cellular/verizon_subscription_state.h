// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_VERIZON_SUBSCRIPTION_STATE_H_
#define SHILL_CELLULAR_VERIZON_SUBSCRIPTION_STATE_H_

#include "shill/cellular/cellular_pco.h"
#include "shill/cellular/subscription_state.h"

namespace shill {

// Finds the Verizon subscription state from the specified PCO. Returns true if
// the PCO contains a Verizon-specific PCO value and |subscription_state| is
// set according to the PCO value. Returns false if no Verizon-specific PCO is
// found.
bool FindVerizonSubscriptionStateFromPco(const CellularPco& pco,
                                         SubscriptionState* subscription_state);

}  // namespace shill

#endif  // SHILL_CELLULAR_VERIZON_SUBSCRIPTION_STATE_H_
