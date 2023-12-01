// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/subscription_state.h"

namespace shill {

std::string SubscriptionStateToString(SubscriptionState subscription_state) {
  switch (subscription_state) {
    case SubscriptionState::kUnknown:
      return "unknown";
    case SubscriptionState::kUnprovisioned:
      return "unprovisioned";
    case SubscriptionState::kProvisioned:
      return "provisioned";
    case SubscriptionState::kOutOfCredits:
      return "out-of-data";
  }
}

}  // namespace shill
