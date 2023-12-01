// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "shill/wifi/wifi_security.h"

#include "shill/dbus-constants.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::Test;

namespace shill {

class WiFiSecurityTest : public Test {
 public:
  WiFiSecurityTest() = default;
  ~WiFiSecurityTest() override = default;
};

TEST(WiFiSecurityTest, BasicNone) {
  WiFiSecurity sec, sec2;
  EXPECT_FALSE(sec.IsValid() || sec2.IsValid());

  sec = WiFiSecurity::kNone;
  sec2 = WiFiSecurity(kSecurityNone);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_FALSE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWep) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWep;
  sec2 = WiFiSecurity(kSecurityWep);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_FALSE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa;
  sec2 = WiFiSecurity(kSecurityWpa);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpaWpa2) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpaWpa2;
  sec2 = WiFiSecurity(kSecurityWpaWpa2);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpaAll) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpaAll;
  sec2 = WiFiSecurity(kSecurityWpaAll);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa2) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa2;
  sec2 = WiFiSecurity(kSecurityWpa2);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa2Wpa3) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa2Wpa3;
  sec2 = WiFiSecurity(kSecurityWpa2Wpa3);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa3) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa3;
  sec2 = WiFiSecurity(kSecurityWpa3);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_TRUE(sec.IsPsk());
  EXPECT_FALSE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAll));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa3));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpaEnterprise) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpaEnterprise;
  sec2 = WiFiSecurity(kSecurityWpaEnterprise);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_TRUE(sec.IsEnterprise());
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAllEnterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Enterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3Enterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3Enterprise));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpaWpa2Enterprise) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpaWpa2Enterprise;
  sec2 = WiFiSecurity(kSecurityWpaWpa2Enterprise);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_TRUE(sec.IsEnterprise());
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAllEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3Enterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3Enterprise));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa2Enterprise) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa2Enterprise;
  sec2 = WiFiSecurity(kSecurityWpa2Enterprise);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_TRUE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAllEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3Enterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa3Enterprise));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa2Wpa3Enterprise) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa2Wpa3Enterprise;
  sec2 = WiFiSecurity(kSecurityWpa2Wpa3Enterprise);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_TRUE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAllEnterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa3Enterprise));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, BasicWpa3Enterprise) {
  WiFiSecurity sec, sec2;

  sec = WiFiSecurity::kWpa3Enterprise;
  sec2 = WiFiSecurity(kSecurityWpa3Enterprise);
  EXPECT_TRUE(sec.IsValid() && sec2.IsValid());
  EXPECT_EQ(sec, sec2);
  EXPECT_TRUE(sec.IsWpa());
  EXPECT_FALSE(sec.IsPsk());
  EXPECT_TRUE(sec.IsEnterprise());
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaEnterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpaWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpaAllEnterprise));
  EXPECT_FALSE(sec.HasCommonMode(WiFiSecurity::kWpa2Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa2Wpa3Enterprise));
  EXPECT_TRUE(sec.HasCommonMode(WiFiSecurity::kWpa3Enterprise));
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
  sec.Freeze();
  EXPECT_EQ(sec, WiFiSecurity(sec.ToString()));
}

TEST(WiFiSecurityTest, CombineSecurityNone) {
  WiFiSecurity sec = WiFiSecurity::kNone;

  EXPECT_EQ(sec.Combine(WiFiSecurity::kNone), WiFiSecurity::kNone);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaAll).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());
}

TEST(WiFiSecurityTest, CombineSecurityWep) {
  WiFiSecurity sec = WiFiSecurity::kWep;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWep), WiFiSecurity::kWep);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaAll).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());
}

TEST(WiFiSecurityTest, CombineSecurityWpa) {
  WiFiSecurity sec = WiFiSecurity::kWpa;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpa);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaAll), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpaAll);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());

  // In the initial phase of deployment "frozen" status should not matter.
  // Let's check this.
  // TODO(b/226138492): Update these checks afterwards (here and below).
  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpaAll);
}

TEST(WiFiSecurityTest, CombineSecurityWpaWpa2) {
  WiFiSecurity sec = WiFiSecurity::kWpaWpa2;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaAll), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpaAll);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpaAll);
}

TEST(WiFiSecurityTest, CombineSecurityWpa2) {
  WiFiSecurity sec = WiFiSecurity::kWpa2;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaAll), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaWpa2);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpa2Wpa3);
}

TEST(WiFiSecurityTest, CombineSecurityWpa2Wpa3) {
  WiFiSecurity sec = WiFiSecurity::kWpa2Wpa3;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaAll), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), sec);
}

TEST(WiFiSecurityTest, CombineSecurityWpa3) {
  WiFiSecurity sec = WiFiSecurity::kWpa3;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaAll), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), WiFiSecurity::kWpa3);
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaEnterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3Enterprise).IsValid());

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2), WiFiSecurity::kWpaAll);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3), WiFiSecurity::kWpa2Wpa3);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3), sec);
}

TEST(WiFiSecurityTest, CombineSecurityWpaEnterprise) {
  WiFiSecurity sec = WiFiSecurity::kWpaEnterprise;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
}

TEST(WiFiSecurityTest, CombineSecurityWpaWpa2Enterprise) {
  WiFiSecurity sec = WiFiSecurity::kWpaWpa2Enterprise;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
}

TEST(WiFiSecurityTest, CombineSecurityWpa2Enterprise) {
  WiFiSecurity sec = WiFiSecurity::kWpa2Enterprise;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaWpa2Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
}

TEST(WiFiSecurityTest, CombineSecurityWpa2Wpa3Enterprise) {
  WiFiSecurity sec = WiFiSecurity::kWpa2Wpa3Enterprise;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise), sec);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise), sec);
}

TEST(WiFiSecurityTest, CombineSecurityWpa3Enterprise) {
  WiFiSecurity sec = WiFiSecurity::kWpa3Enterprise;

  EXPECT_FALSE(sec.Combine(WiFiSecurity::kNone).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWep).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpaWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa2Wpa3).IsValid());
  EXPECT_FALSE(sec.Combine(WiFiSecurity::kWpa3).IsValid());
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise),
            WiFiSecurity::kWpa3Enterprise);

  sec.Freeze();
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaEnterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpaWpa2Enterprise),
            WiFiSecurity::kWpaAllEnterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa2Wpa3Enterprise),
            WiFiSecurity::kWpa2Wpa3Enterprise);
  EXPECT_EQ(sec.Combine(WiFiSecurity::kWpa3Enterprise), sec);
}

}  // namespace shill
