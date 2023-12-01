// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_MOCK_SUPPLICANT_BSS_PROXY_H_
#define SHILL_SUPPLICANT_MOCK_SUPPLICANT_BSS_PROXY_H_

#include <gmock/gmock.h>

#include "shill/supplicant/supplicant_bss_proxy_interface.h"

namespace shill {

class MockSupplicantBSSProxy : public SupplicantBSSProxyInterface {
 public:
  MockSupplicantBSSProxy();
  MockSupplicantBSSProxy(const MockSupplicantBSSProxy&) = delete;
  MockSupplicantBSSProxy& operator=(const MockSupplicantBSSProxy&) = delete;

  ~MockSupplicantBSSProxy() override;

  MOCK_METHOD(void, Die, ());  // So we can EXPECT the dtor.
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_MOCK_SUPPLICANT_BSS_PROXY_H_
