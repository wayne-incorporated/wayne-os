// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <memory>
#include <vector>

#include "shill/cellular/verizon_subscription_state.h"

#include <base/logging.h>

namespace shill {
namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Turn off logging.
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  const std::vector<uint8_t> raw_data(data, data + size);
  std::unique_ptr<CellularPco> pco = CellularPco::CreateFromRawData(raw_data);
  if (pco) {
    SubscriptionState subscription_state;
    FindVerizonSubscriptionStateFromPco(*pco, &subscription_state);
  }

  return 0;
}

}  // namespace
}  // namespace shill
