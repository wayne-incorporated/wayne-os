// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_MOCK_EAP_LISTENER_H_
#define SHILL_ETHERNET_MOCK_EAP_LISTENER_H_

#include "shill/ethernet/eap_listener.h"

#include <gmock/gmock.h>

namespace shill {

class MockEapListener : public EapListener {
 public:
  MockEapListener();
  MockEapListener(const MockEapListener&) = delete;
  MockEapListener& operator=(const MockEapListener&) = delete;

  ~MockEapListener() override;

  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void,
              set_request_received_callback,
              (const EapListener::EapRequestReceivedCallback&),
              (override));
};

}  // namespace shill

#endif  // SHILL_ETHERNET_MOCK_EAP_LISTENER_H_
