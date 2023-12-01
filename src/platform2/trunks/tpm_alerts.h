// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_ALERTS_H_
#define TRUNKS_TPM_ALERTS_H_

namespace trunks {

enum TpmChipFamily {
  kFamilyUndefined = 0,
  kFamilyH1 = 1,
};

const size_t kH1AlertsSize = 44;

// Maximum possible size of alerts array returned by the firmware
const size_t kAlertsMaxSize = 44;

// This structure is specified in Cr50 firmware
struct TpmAlertsData {
  uint16_t chip_family;  // it defines what alerts we get from firmware
  uint16_t alerts_num;
  uint16_t counters[kAlertsMaxSize];
} __attribute__((packed));

}  // namespace trunks

#endif  // TRUNKS_TPM_ALERTS_H_
