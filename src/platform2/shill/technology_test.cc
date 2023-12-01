// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/technology.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/error.h"

using testing::ElementsAre;

namespace shill {

TEST(TechnologyTest, TechnologyFromName) {
  EXPECT_EQ(Technology::kEthernet, TechnologyFromName("ethernet"));
  EXPECT_EQ(Technology::kEthernetEap, TechnologyFromName("etherneteap"));
  EXPECT_EQ(Technology::kWiFi, TechnologyFromName("wifi"));
  EXPECT_EQ(Technology::kCellular, TechnologyFromName("cellular"));
  EXPECT_EQ(Technology::kTunnel, TechnologyFromName("tunnel"));
  EXPECT_EQ(Technology::kLoopback, TechnologyFromName("loopback"));
  EXPECT_EQ(Technology::kVPN, TechnologyFromName("vpn"));
  EXPECT_EQ(Technology::kPPP, TechnologyFromName("ppp"));
  EXPECT_EQ(Technology::kGuestInterface, TechnologyFromName("guest_interface"));
  EXPECT_EQ(Technology::kUnknown, TechnologyFromName("foo"));
  EXPECT_EQ(Technology::kUnknown, TechnologyFromName(""));
}

TEST(TechnologyTest, TechnologyName) {
  EXPECT_EQ("ethernet", TechnologyName(Technology::kEthernet));
  EXPECT_EQ("etherneteap", TechnologyName(Technology::kEthernetEap));
  EXPECT_EQ("wifi", TechnologyName(Technology::kWiFi));
  EXPECT_EQ("cellular", TechnologyName(Technology::kCellular));
  EXPECT_EQ("tunnel", TechnologyName(Technology::kTunnel));
  EXPECT_EQ("loopback", TechnologyName(Technology::kLoopback));
  EXPECT_EQ("vpn", TechnologyName(Technology::kVPN));
  EXPECT_EQ("ppp", TechnologyName(Technology::kPPP));
  EXPECT_EQ("guest_interface", TechnologyName(Technology::kGuestInterface));
  EXPECT_EQ("unknown", TechnologyName(Technology::kUnknown));
}

TEST(TechnologyTest, TechnologyFromStorageGroup) {
  EXPECT_EQ(Technology::kVPN, TechnologyFromStorageGroup("vpn"));
  EXPECT_EQ(Technology::kVPN, TechnologyFromStorageGroup("vpn_a"));
  EXPECT_EQ(Technology::kVPN, TechnologyFromStorageGroup("vpn__a"));
  EXPECT_EQ(Technology::kVPN, TechnologyFromStorageGroup("vpn_a_1"));
  EXPECT_EQ(Technology::kUnknown, TechnologyFromStorageGroup("_vpn"));
  EXPECT_EQ(Technology::kUnknown, TechnologyFromStorageGroup("_"));
  EXPECT_EQ(Technology::kUnknown, TechnologyFromStorageGroup(""));
}

TEST(TechnologyTest, GetTechnologyVectorFromStringWithValidTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_TRUE(GetTechnologyVectorFromString("", &technologies, &error));
  EXPECT_THAT(technologies, ElementsAre());
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(GetTechnologyVectorFromString("ethernet", &technologies, &error));
  EXPECT_THAT(technologies, ElementsAre(Technology::kEthernet));
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(
      GetTechnologyVectorFromString("ethernet,vpn", &technologies, &error));
  EXPECT_THAT(technologies,
              ElementsAre(Technology::kEthernet, Technology::kVPN));
  EXPECT_TRUE(error.IsSuccess());

  EXPECT_TRUE(GetTechnologyVectorFromString("wifi,ethernet,vpn", &technologies,
                                            &error));
  EXPECT_THAT(
      technologies,
      ElementsAre(Technology::kWiFi, Technology::kEthernet, Technology::kVPN));
  EXPECT_TRUE(error.IsSuccess());
}

TEST(TechnologyTest, GetTechnologyVectorFromStringWithInvalidTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_FALSE(GetTechnologyVectorFromString("foo", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("foo is an unknown technology name", error.message());

  EXPECT_FALSE(
      GetTechnologyVectorFromString("ethernet,bar", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("bar is an unknown technology name", error.message());

  EXPECT_FALSE(
      GetTechnologyVectorFromString("ethernet,foo,vpn", &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("foo is an unknown technology name", error.message());
}

TEST(TechnologyTest,
     GetTechnologyVectorFromStringWithDuplicateTechnologyNames) {
  std::vector<Technology> technologies;
  Error error;

  EXPECT_FALSE(GetTechnologyVectorFromString("ethernet,vpn,ethernet",
                                             &technologies, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("ethernet is duplicated in the list", error.message());
}

}  // namespace shill
