// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_SUBSCRIPTION_STATE_H_
#define SHILL_CELLULAR_SUBSCRIPTION_STATE_H_

#include <string>

namespace shill {

// CellularSubscriptionState represents the provisioned state of SIM. It is used
// currently by activation logic for LTE to determine if activation process is
// complete.
enum class SubscriptionState {
  kUnknown,
  kUnprovisioned,
  kProvisioned,
  kOutOfCredits,
};

std::string SubscriptionStateToString(SubscriptionState subscription_state);

}  // namespace shill

#endif  // SHILL_CELLULAR_SUBSCRIPTION_STATE_H_
