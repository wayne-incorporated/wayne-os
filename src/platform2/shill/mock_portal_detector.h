// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_PORTAL_DETECTOR_H_
#define SHILL_MOCK_PORTAL_DETECTOR_H_

#include "shill/portal_detector.h"

#include <string>
#include <vector>

#include <base/time/time.h>
#include <gmock/gmock.h>

#include "shill/net/ip_address.h"

namespace shill {

class MockPortalDetector : public PortalDetector {
 public:
  MockPortalDetector();
  MockPortalDetector(const MockPortalDetector&) = delete;
  MockPortalDetector& operator=(const MockPortalDetector&) = delete;

  ~MockPortalDetector() override;

  MOCK_METHOD(bool,
              Start,
              (const std::string& ifname,
               const IPAddress&,
               const std::vector<std::string>&,
               const std::string& logging_tag,
               base::TimeDelta),
              (override));
  MOCK_METHOD(bool,
              Restart,
              (const std::string& ifname,
               const IPAddress&,
               const std::vector<std::string>&,
               const std::string& logging_tag),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, IsInProgress, (), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_PORTAL_DETECTOR_H_
