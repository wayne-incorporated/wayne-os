// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_MOCK_NETLINK_MANAGER_H_
#define SHILL_NET_MOCK_NETLINK_MANAGER_H_

#include "shill/net/netlink_manager.h"

#include <string>

#include <gmock/gmock.h>

namespace shill {

class MockNetlinkManager : public NetlinkManager {
 public:
  MockNetlinkManager();
  MockNetlinkManager(const MockNetlinkManager&) = delete;
  MockNetlinkManager& operator=(const MockNetlinkManager&) = delete;

  ~MockNetlinkManager() override;

  MOCK_METHOD(bool, Init, (), (override));
  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(uint16_t,
              GetFamily,
              (const std::string&, const NetlinkMessageFactory::FactoryMethod&),
              (override));
  MOCK_METHOD(bool,
              RemoveBroadcastHandler,
              (const NetlinkMessageHandler&),
              (override));
  MOCK_METHOD(bool,
              AddBroadcastHandler,
              (const NetlinkMessageHandler&),
              (override));
  MOCK_METHOD(bool,
              SendControlMessage,
              (ControlNetlinkMessage*,
               const ControlNetlinkMessageHandler&,
               const NetlinkAckHandler&,
               const NetlinkAuxiliaryMessageHandler&),
              (override));
  MOCK_METHOD(bool,
              SendNl80211Message,
              (Nl80211Message*,
               const Nl80211MessageHandler&,
               const NetlinkAckHandler&,
               const NetlinkAuxiliaryMessageHandler&),
              (override));
  MOCK_METHOD(bool,
              SubscribeToEvents,
              (const std::string&, const std::string&),
              (override));
};

}  // namespace shill

#endif  // SHILL_NET_MOCK_NETLINK_MANAGER_H_
