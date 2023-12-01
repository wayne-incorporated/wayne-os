// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h"

#include <base/logging.h>

namespace hwsec_foundation {

namespace {

TpmMetricsClientID currentTpmMetricsClientID = TpmMetricsClientID::kUnknown;

}  // namespace

void SetTpmMetricsClientID(TpmMetricsClientID id) {
  currentTpmMetricsClientID = id;
}

TpmMetricsClientID GetTpmMetricsClientID() {
  return currentTpmMetricsClientID;
}

}  // namespace hwsec_foundation
