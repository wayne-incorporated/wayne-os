// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_CELLULAR_H_
#define SHILL_CELLULAR_MOCK_CELLULAR_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/cellular.h"

namespace shill {

class MockCellular : public Cellular {
 public:
  MockCellular(Manager* manager,
               const std::string& link_name,
               const std::string& address,
               int interface_index,
               const std::string& service,
               const RpcIdentifier& path);
  MockCellular(const MockCellular&) = delete;
  MockCellular& operator=(const MockCellular&) = delete;

  ~MockCellular() override;

  MOCK_METHOD(void, Connect, (CellularService*, Error*), (override));
  MOCK_METHOD(void, Disconnect, (Error*, const char*), (override));
  MOCK_METHOD(void, ReAttach, (), (override));
  MOCK_METHOD(void, StartPPP, (const std::string&), (override));
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_CELLULAR_H_
