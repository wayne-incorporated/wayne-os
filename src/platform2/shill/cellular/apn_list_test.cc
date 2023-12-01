// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/apn_list.h"

#include <gtest/gtest.h>

#include <base/containers/contains.h>
#include <chromeos/dbus/service_constants.h>
#include "dbus/shill/dbus-constants.h"

using testing::Test;

namespace shill {

TEST(ApnListTest, AddApnWithMerge) {
  std::vector<MobileOperatorMapper::MobileAPN> mobile_apns;
  MobileOperatorMapper::MobileAPN mobile_apn1;
  mobile_apn1.apn = "apn1";
  mobile_apn1.ip_type = "IPV4";
  mobile_apn1.apn_types = {"DEFAULT", "IA"};
  mobile_apn1.username = "user1";
  mobile_apn1.password = "pass1";
  mobile_apn1.authentication = "PAP";
  mobile_apn1.operator_name_list = {{"OPERATOR", ""}, {"OPERADORA", "ES"}};

  MobileOperatorMapper::MobileAPN mobile_apn2;
  mobile_apn2.apn = "apn2";
  mobile_apn2.ip_type = "IPV4V6";
  mobile_apn2.apn_types = {"DEFAULT", "DUN"};
  mobile_apn2.username = "user2";
  mobile_apn2.password = "pass2";
  mobile_apn2.authentication = "CHAP";

  mobile_apns.push_back(mobile_apn1);
  mobile_apns.push_back(mobile_apn2);
  ApnList apn_list(/*merge_similar_apns*/ true);
  apn_list.AddApns(mobile_apns, ApnList::ApnSource::kModem);

  Stringmaps apns = apn_list.GetList();
  ASSERT_EQ(apns.size(), 2);

  Stringmap* apn = &apns.at(0);

  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn1");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4");
  EXPECT_TRUE(ApnList::IsAttachApn(*apn));
  EXPECT_TRUE(ApnList::IsDefaultApn(*apn));
  EXPECT_STREQ(apn->at(kApnTypesProperty).c_str(),
               ApnList::JoinApnTypes({"DEFAULT", "IA"}).c_str());
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user1");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass1");
  EXPECT_STREQ(apn->at(kApnAuthenticationProperty).c_str(), "PAP");
  EXPECT_STREQ(apn->at(kApnSourceProperty).c_str(), cellular::kApnSourceModem);
  EXPECT_STREQ(apn->at(kApnNameProperty).c_str(), "OPERATOR");
  EXPECT_STREQ(apn->at(kApnLocalizedNameProperty).c_str(), "OPERADORA");

  apn = &apns.at(1);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn2");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4V6");
  EXPECT_FALSE(ApnList::IsAttachApn(*apn));
  EXPECT_TRUE(ApnList::IsDefaultApn(*apn));
  EXPECT_TRUE(ApnList::IsTetheringApn(*apn));
  EXPECT_STREQ(apn->at(kApnTypesProperty).c_str(), "DEFAULT,DUN");
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user2");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass2");
  EXPECT_STREQ(apn->at(kApnAuthenticationProperty).c_str(), "CHAP");
  EXPECT_STREQ(apn->at(kApnSourceProperty).c_str(), cellular::kApnSourceModem);
  EXPECT_FALSE(base::Contains(*apn, kApnNameProperty));
  EXPECT_FALSE(base::Contains(*apn, kApnLocalizedNameProperty));

  std::vector<MobileOperatorMapper::MobileAPN> mobile_apns2;
  mobile_apn1.operator_name_list = {{"OPERATOR3", ""}};
  mobile_apns2.push_back(mobile_apn1);

  // This should update the first entry.
  apn_list.AddApns(mobile_apns2, ApnList::ApnSource::kModb);
  apns = apn_list.GetList();
  ASSERT_EQ(apns.size(), 2);
  apn = &apns.at(0);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn1");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4");
  EXPECT_TRUE(ApnList::IsAttachApn(*apn));
  EXPECT_STREQ(apn->at(kApnTypesProperty).c_str(),
               ApnList::JoinApnTypes({"DEFAULT", "IA"}).c_str());
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user1");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass1");
  EXPECT_STREQ(apn->at(kApnAuthenticationProperty).c_str(), "PAP");
  EXPECT_STREQ(apn->at(kApnSourceProperty).c_str(), cellular::kApnSourceMoDb);
  EXPECT_STREQ(apn->at(kApnNameProperty).c_str(), "OPERATOR3");
  EXPECT_STREQ(apn->at(kApnLocalizedNameProperty).c_str(), "OPERADORA");
}

TEST(ApnListTest, AddApnWithoutMerge) {
  std::vector<MobileOperatorMapper::MobileAPN> mobile_apns;
  MobileOperatorMapper::MobileAPN mobile_apn1;
  mobile_apn1.apn = "apn1";
  mobile_apn1.ip_type = "IPV4";
  mobile_apn1.apn_types = {"DEFAULT", "IA"};
  mobile_apn1.username = "user1";
  mobile_apn1.password = "pass1";
  mobile_apn1.authentication = "PAP";
  mobile_apn1.operator_name_list = {{"OPERATOR", ""}, {"OPERADORA", "ES"}};

  MobileOperatorMapper::MobileAPN mobile_apn2;
  mobile_apn2.apn = "apn2";
  mobile_apn2.ip_type = "IPV4V6";
  mobile_apn2.apn_types = {"DEFAULT"};
  mobile_apn2.username = "user2";
  mobile_apn2.password = "pass2";
  mobile_apn2.authentication = "CHAP";

  mobile_apns.push_back(mobile_apn1);
  mobile_apns.push_back(mobile_apn2);
  mobile_apns.push_back(mobile_apn2);

  ApnList apn_list(/*merge_similar_apns*/ false);
  apn_list.AddApns(mobile_apns, ApnList::ApnSource::kModem);

  Stringmaps apns = apn_list.GetList();
  ASSERT_EQ(apns.size(), 3);

  Stringmap* apn = &apns.at(0);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn1");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4");
  EXPECT_TRUE(ApnList::IsAttachApn(*apn));
  EXPECT_STREQ(apn->at(kApnTypesProperty).c_str(),
               ApnList::JoinApnTypes({"DEFAULT", "IA"}).c_str());
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user1");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass1");
  EXPECT_STREQ(apn->at(kApnAuthenticationProperty).c_str(), "PAP");
  EXPECT_STREQ(apn->at(kApnSourceProperty).c_str(), cellular::kApnSourceModem);
  EXPECT_STREQ(apn->at(kApnNameProperty).c_str(), "OPERATOR");
  EXPECT_STREQ(apn->at(kApnLocalizedNameProperty).c_str(), "OPERADORA");

  apn = &apns.at(1);
  EXPECT_STREQ(apn->at(kApnProperty).c_str(), "apn2");
  EXPECT_STREQ(apn->at(kApnIpTypeProperty).c_str(), "IPV4V6");
  EXPECT_FALSE(ApnList::IsAttachApn(*apn));
  EXPECT_STREQ(apn->at(kApnTypesProperty).c_str(), "DEFAULT");
  EXPECT_STREQ(apn->at(kApnUsernameProperty).c_str(), "user2");
  EXPECT_STREQ(apn->at(kApnPasswordProperty).c_str(), "pass2");
  EXPECT_STREQ(apn->at(kApnAuthenticationProperty).c_str(), "CHAP");
  EXPECT_STREQ(apn->at(kApnSourceProperty).c_str(), cellular::kApnSourceModem);
  EXPECT_FALSE(base::Contains(*apn, kApnNameProperty));
  EXPECT_FALSE(base::Contains(*apn, kApnLocalizedNameProperty));

  EXPECT_EQ(apns.at(1), apns.at(2));
}

}  // namespace shill
