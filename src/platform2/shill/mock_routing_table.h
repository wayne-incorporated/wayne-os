// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ROUTING_TABLE_H_
#define SHILL_MOCK_ROUTING_TABLE_H_

#include <gmock/gmock.h>

#include "shill/routing_table.h"

namespace shill {

class MockRoutingTable : public RoutingTable {
 public:
  MockRoutingTable();
  MockRoutingTable(const MockRoutingTable&) = delete;
  MockRoutingTable& operator=(const MockRoutingTable&) = delete;

  ~MockRoutingTable() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, AddRoute, (int, const RoutingTableEntry&), (override));
  MOCK_METHOD(bool,
              GetDefaultRoute,
              (int, IPAddress::Family, RoutingTableEntry*),
              (override));
  MOCK_METHOD(bool,
              GetDefaultRouteFromKernel,
              (int, RoutingTableEntry*),
              (override));
  MOCK_METHOD(bool,
              SetDefaultRoute,
              (int, const IPAddress&, uint32_t),
              (override));
  MOCK_METHOD(bool,
              CreateBlackholeRoute,
              (int, IPAddress::Family, uint32_t, uint32_t),
              (override));
  MOCK_METHOD(bool,
              CreateLinkRoute,
              (int, const IPAddress&, const IPAddress&, uint32_t),
              (override));
  MOCK_METHOD(void, FlushRoutes, (int), (override));
  MOCK_METHOD(void, FlushRoutesWithTag, (int), (override));
  MOCK_METHOD(bool, FlushCache, (), (override));
  MOCK_METHOD(void, ResetTable, (int), (override));
  MOCK_METHOD(bool,
              RequestRouteToHost,
              (const IPAddress&, int, QueryCallback),
              (override));
  MOCK_METHOD(bool, AddRule, (int, const RoutingPolicyEntry&), (override));
  MOCK_METHOD(void, FlushRules, (int), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_ROUTING_TABLE_H_
