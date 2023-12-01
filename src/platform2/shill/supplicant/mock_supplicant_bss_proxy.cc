// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/mock_supplicant_bss_proxy.h"

namespace shill {

MockSupplicantBSSProxy::MockSupplicantBSSProxy() = default;

MockSupplicantBSSProxy::~MockSupplicantBSSProxy() {
  Die();
}

}  // namespace shill
