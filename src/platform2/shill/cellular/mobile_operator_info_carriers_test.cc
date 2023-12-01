// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "shill/cellular/mobile_operator_info.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <gtest/gtest.h>

#include "shill/cellular/apn_list.h"
#include "shill/cellular/mobile_operator_mapper.h"
#include "shill/dbus-constants.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/test_event_dispatcher.h"

using std::string;
using testing::Test;

// The tests in this file are meant to ensure there are no regressions on the
// most popular carriers. These test will be validated using
// service_providers.textproto and will use the real MobileOperatorMappers.

namespace shill {

class ApnBuilder {
 public:
  ApnBuilder() {
    // Set ip_type to ipv4 by default to match the behavior of the proto
    apn_.ip_type = kApnIpTypeV4;
  }
  explicit ApnBuilder(std::string apn_name) : ApnBuilder() { Name(apn_name); }

  const MobileOperatorMapper::MobileAPN& apn() { return apn_; }
  ApnBuilder& Name(const string value) {
    apn_.apn = value;
    return *this;
  }
  ApnBuilder& Username(const string value) {
    apn_.username = value;
    return *this;
  }
  ApnBuilder& Password(const string value) {
    apn_.password = value;
    return *this;
  }
  ApnBuilder& Auth(const string value) {
    apn_.authentication = value;
    return *this;
  }
  ApnBuilder& ApnTypes(const std::set<std::string> value) {
    apn_.apn_types = value;
    return *this;
  }
  ApnBuilder& IpType(const string value) {
    apn_.ip_type = value;
    return *this;
  }
  ApnBuilder& IsRequiredByCarrierSpec(bool value) {
    apn_.is_required_by_carrier_spec = value;
    return *this;
  }
  ApnBuilder& OperatorNameList(
      const std::vector<MobileOperatorMapper::LocalizedName> value) {
    apn_.operator_name_list = value;
    return *this;
  }

 private:
  MobileOperatorMapper::MobileAPN apn_;
};

class MobileOperatorInfoCarriersTest : public Test {
 public:
  MobileOperatorInfoCarriersTest()
      :  // TODO(b/266738838): validate the list of MCCMNCs for AT&T.
        kAttUsMccmncs({"310030", "310038", "310070", "310090", "310150",
                       "310170", "310280", "310380", "310410", "310560",
                       "310670", "310680", "310950", "310980", "311180",
                       "312670", "313100", "313110", "313120", "313130",
                       "313140", "313790"}),
        kVerizonUsMccmncs({"310995", "311270", "311480"}),
        kTmobileUsMccmncs({"310026", "310160", "310200", "310210", "310220",
                           "310230", "310240", "310250", "310260", "310270",
                           "310310", "310490", "310580", "310660", "310800",
                           "311882", "312250"}) {
    operator_info_ = std::make_unique<MobileOperatorInfo>(&dispatcher_, "test");
  }
  MobileOperatorInfoCarriersTest(const MobileOperatorInfoCarriersTest&) =
      delete;
  MobileOperatorInfoCarriersTest& operator=(
      const MobileOperatorInfoCarriersTest&) = delete;

  void SetUp() override {
    shill::ScopeLogger::GetInstance()->set_verbose_level(1);
    shill::ScopeLogger::GetInstance()->EnableScopesByName("cellular");
    operator_info_->ClearDatabasePaths();
    const char* out_dir = getenv("OUT");
    CHECK_NE(out_dir, nullptr);
    base::FilePath database_path =
        base::FilePath(out_dir).Append("serviceproviders.pbf");

    operator_info_->AddDatabasePath(database_path);
    operator_info_->Init();
  }

 protected:
  MobileOperatorMapper::MobileAPN PrepareModbApnForComparison(
      MobileOperatorMapper::MobileAPN apn) {
    // Ignore operator name list
    apn.operator_name_list.clear();
    return apn;
  }
  void CheckIfApnExists(ApnBuilder apn_builder) {
    for (const auto& apn_info : operator_info_->apn_list()) {
      if (PrepareModbApnForComparison(apn_info) == apn_builder.apn())
        return;
    }
    FAIL() << "APN: " << apn_builder.apn().apn << " not found";
  }
  string ApnToString(MobileOperatorMapper::MobileAPN apn) {
    return base::StringPrintf(
        "{apn: %s, username: %s, password: %s, authentication: %s, ip_type: %s "
        ", apn_types: %s , operator_name_list.size(): %s, "
        "is_required_by_carrier_spec: %d}",
        apn.apn.c_str(), apn.username.c_str(), apn.password.c_str(),
        apn.authentication.c_str(), apn.ip_type.c_str(),
        ApnList::JoinApnTypes(
            std::vector<string>(apn.apn_types.begin(), apn.apn_types.end()))
            .c_str(),
        base::NumberToString(apn.operator_name_list.size()).c_str(),
        apn.is_required_by_carrier_spec);
  }

  void CheckFirstApn(ApnBuilder apn_builder) {
    EXPECT_GT(operator_info_->apn_list().size(), 0);
    auto apn = PrepareModbApnForComparison(operator_info_->apn_list()[0]);
    EXPECT_EQ(apn, apn_builder.apn())
        << " operator_info_->apn_list()[0]:" << ApnToString(apn)
        << " \napn_builder.apn():" << ApnToString(apn_builder.apn());
  }

  std::string CreateRandomGid1NotInSet(std::set<std::string> gid1s) {
    while (true) {
      int gid1 = base::RandInt(0, 0xFFFF);
      std::string gid1_s = base::HexEncode(&gid1, 2);
      if (gid1s.count(gid1_s) == 0)
        return gid1_s;
    }
  }

  std::string CreateRandomMccmnc(std::string prefix, int len) {
    // Create a 7 digit number and remove the first digit to ensure the 6 digit
    // number is padded on the left. Then add the prefix, and remove any extra
    // digits on the right.
    std::string value = base::StrCat(
        {prefix,
         base::NumberToString(base::RandInt(1000000, 1999999)).substr(1, 6)});
    return value.substr(0, len);
  }

  EventDispatcherForTest dispatcher_;
  std::unique_ptr<MobileOperatorInfo> operator_info_;

  static constexpr char kUnknownMccmnc[] = "000000";
  const std::set<string> kAttUsMccmncs;
  const std::set<string> kVerizonUsMccmncs;
  const std::set<string> kTmobileUsMccmncs;
};

class MobileOperatorInfoCarriersAttTest
    : public MobileOperatorInfoCarriersTest {
 public:
  MobileOperatorInfoCarriersAttTest()
      : kAttApn4G(ApnBuilder("broadband")
                      .IpType(kApnIpTypeV4V6)
                      .ApnTypes({kApnTypeDefault, kApnTypeIA})),
        kAttApn5G(ApnBuilder("nrbroadband")
                      .IpType(kApnIpTypeV4V6)
                      .ApnTypes({kApnTypeDefault, kApnTypeIA})),
        kAttApn5GC(ApnBuilder("5gcbroadband")
                       .IpType(kApnIpTypeV4V6)
                       .ApnTypes({kApnTypeDefault, kApnTypeIA})),
        kAttApnHotspot(ApnBuilder("hotspot")
                           .IpType(kApnIpTypeV4V6)
                           .IsRequiredByCarrierSpec(true)
                           .ApnTypes({kApnTypeDun})),
        kAtt5gMccmncs({"310410", "310280", "311180", "310950"}),
        kAttMxMccmncs({"334050", "334090"}),
        kCricketMccmncs({"310150"}),
        kFirstnetMccmncs(
            {"312670", "313100", "313110", "313120", "313130", "313140"}) {}

 protected:
  std::vector<string> GetUsMnoOnlyMccmncs() {
    std::vector<string> value;
    for (auto& mccmnc : kAttUsMccmncs) {
      if (!kCricketMccmncs.count(mccmnc) && !kFirstnetMccmncs.count(mccmnc))
        value.push_back(mccmnc);
    }
    return value;
  }

  const ApnBuilder kAttApn4G;
  const ApnBuilder kAttApn5G;
  const ApnBuilder kAttApn5GC;
  const ApnBuilder kAttApnHotspot;

  const std::set<string> kAtt5gMccmncs;
  const std::set<string> kAttMxMccmncs;
  const std::set<string> kCricketMccmncs;
  const std::set<string> kFirstnetMccmncs;

  static constexpr int kAttMtu = 1430;
  static constexpr char kAttOperatorName[] = "AT&T";
};

TEST_F(MobileOperatorInfoCarriersAttTest, AttUsHome_AttServing) {
  for (const auto& mccmnc : GetUsMnoOnlyMccmncs()) {
    operator_info_->UpdateMCCMNC(mccmnc);
    operator_info_->UpdateServingMCCMNC(mccmnc);
    EXPECT_EQ(operator_info_->operator_name(), kAttOperatorName);
    EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
    EXPECT_EQ(operator_info_->mtu(), kAttMtu);
    operator_info_->UpdateGID1(CreateRandomGid1NotInSet({"52FF", "53FF"}));
    CheckFirstApn(kAttApn4G);
    CheckIfApnExists(kAttApnHotspot);
  }
}

TEST_F(MobileOperatorInfoCarriersAttTest, UnknownHome_AttServing) {
  operator_info_->UpdateMCCMNC(kUnknownMccmnc);
  operator_info_->UpdateServingMCCMNC(GetUsMnoOnlyMccmncs()[0]);
  EXPECT_EQ(operator_info_->operator_name(), "");
  EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
  EXPECT_EQ(operator_info_->mtu(), kAttMtu);
  EXPECT_EQ(operator_info_->apn_list().size(), 0);
}

TEST_F(MobileOperatorInfoCarriersAttTest, AttHome_UnknownServing) {
  operator_info_->UpdateMCCMNC(*kAttUsMccmncs.begin());
  operator_info_->UpdateServingMCCMNC(kUnknownMccmnc);
  EXPECT_EQ(operator_info_->operator_name(), kAttOperatorName);
  EXPECT_EQ(operator_info_->serving_operator_name(), "");
  EXPECT_EQ(operator_info_->mtu(), kAttMtu);
  CheckFirstApn(kAttApn4G);
  CheckIfApnExists(kAttApnHotspot);
}

TEST_F(MobileOperatorInfoCarriersAttTest, Att5gUsHome_AttServing) {
  for (const auto& home : kAtt5gMccmncs) {
    for (const auto& serving : GetUsMnoOnlyMccmncs()) {
      operator_info_->UpdateMCCMNC(home);
      operator_info_->UpdateServingMCCMNC(serving);
      // ATT 5G has an GID1 filter
      operator_info_->UpdateGID1("53FF");
      EXPECT_EQ(operator_info_->operator_name(), kAttOperatorName);
      EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
      EXPECT_EQ(operator_info_->mtu(), kAttMtu);
      CheckFirstApn(kAttApn5G);
      CheckIfApnExists(kAttApn4G);
      CheckIfApnExists(kAttApnHotspot);
    }
  }
}

TEST_F(MobileOperatorInfoCarriersAttTest, Att5gcUsHome_AttServing) {
  for (const auto& home : kAtt5gMccmncs) {
    for (const auto& serving : GetUsMnoOnlyMccmncs()) {
      operator_info_->UpdateMCCMNC(home);
      operator_info_->UpdateServingMCCMNC(serving);
      // ATT 5GC has an GID1 filter
      operator_info_->UpdateGID1("52FF");
      EXPECT_EQ(operator_info_->operator_name(), kAttOperatorName);
      EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
      EXPECT_EQ(operator_info_->mtu(), kAttMtu);
      CheckFirstApn(kAttApn5GC);
      CheckIfApnExists(kAttApn4G);
      CheckIfApnExists(kAttApnHotspot);
    }
  }
}

TEST_F(MobileOperatorInfoCarriersAttTest, CricketHome_AttServing) {
  for (const auto& home : kCricketMccmncs) {
    for (const auto& serving : GetUsMnoOnlyMccmncs()) {
      operator_info_->UpdateMCCMNC(home);
      operator_info_->UpdateServingMCCMNC(serving);
      // Cricket has an OPERATOR_NAME filter
      operator_info_->UpdateOperatorName("Cricket");
      EXPECT_EQ(operator_info_->operator_name(), "Cricket");
      EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
      EXPECT_EQ(operator_info_->mtu(), 1430 /* Cricket mtu */);
      CheckFirstApn(ApnBuilder("mht").ApnTypes({kApnTypeDefault, kApnTypeIA}));
    }
  }
}

TEST_F(MobileOperatorInfoCarriersAttTest, FirstnetHome_AttServing) {
  for (const auto& home : kFirstnetMccmncs) {
    for (const auto& serving : GetUsMnoOnlyMccmncs()) {
      // Firstnet has an MCCMNC filter
      operator_info_->UpdateMCCMNC(home);
      operator_info_->UpdateServingMCCMNC(serving);
      EXPECT_EQ(operator_info_->operator_name(), "firstnet");
      EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
      // Even though firstnet might use AT&T as serving operator, the firstnet
      // mtu is smaller than AT&T's, so it'a always chosen.
      EXPECT_EQ(operator_info_->mtu(), 1342);
      CheckFirstApn(ApnBuilder("firstnet-broadband")
                        .ApnTypes({kApnTypeDefault, kApnTypeIA}));
      if (home != "313110" && home != "313120")
        CheckIfApnExists(ApnBuilder("firstnet-hotspot")
                             .IsRequiredByCarrierSpec(true)
                             .ApnTypes({kApnTypeDun}));
    }
  }
}

TEST_F(MobileOperatorInfoCarriersAttTest, AttMxHome_AttMxServing) {
  for (const auto& mccmnc : kAttMxMccmncs) {
    operator_info_->UpdateMCCMNC(mccmnc);
    operator_info_->UpdateServingMCCMNC(mccmnc);
    EXPECT_EQ(operator_info_->operator_name(), kAttOperatorName);
    EXPECT_EQ(operator_info_->serving_operator_name(), kAttOperatorName);
    EXPECT_EQ(operator_info_->mtu(), IPConfig::kUndefinedMTU);
    CheckFirstApn(kAttApn4G);
  }
}

class MobileOperatorInfoCarriersUsCellularTest
    : public MobileOperatorInfoCarriersTest {
 public:
  MobileOperatorInfoCarriersUsCellularTest()
      : kUsCellularApn(ApnBuilder("usccinternet").ApnTypes({kApnTypeDefault})),
        kUsCellularMccmncs({"311580", "311581", "311582", "311583", "311584",
                            "311585", "311586", "311587", "311588", "311589"}) {
  }

 protected:
  std::vector<string> GetMccmncsFromAllUsCarriers() {
    std::vector<string> value;
    for (auto& mccmnc : kAttUsMccmncs)
      value.push_back(mccmnc);
    for (auto& mccmnc : kVerizonUsMccmncs)
      value.push_back(mccmnc);
    for (auto& mccmnc : kTmobileUsMccmncs)
      value.push_back(mccmnc);
    return value;
  }

  const ApnBuilder kUsCellularApn;
  const std::set<string> kUsCellularMccmncs;
  static constexpr char kUsCellularOperatorName[] = "US Cellular";
};

TEST_F(MobileOperatorInfoCarriersUsCellularTest, RoamOnUsCarriers) {
  std::vector<string> serving_mccmncs = GetMccmncsFromAllUsCarriers();
  // Append random MCCMNC's in the range `31[0-6]...` to test unknown US
  // MCCMNCs.
  for (int i = 0; i < 7; i++) {
    serving_mccmncs.push_back(
        CreateRandomMccmnc(base::StrCat({"31", base::NumberToString(i)}), 6));
  }
  for (const auto& serving_mccmnc : serving_mccmncs) {
    for (const auto& mccmnc : kUsCellularMccmncs) {
      operator_info_->UpdateMCCMNC(mccmnc);
      operator_info_->UpdateServingMCCMNC(serving_mccmnc);
      EXPECT_EQ(operator_info_->operator_name(), kUsCellularOperatorName);
      EXPECT_EQ(operator_info_->requires_roaming(), true)
          << " serving_mccmnc: " << serving_mccmnc;
      CheckFirstApn(kUsCellularApn);
    }
  }
}

TEST_F(MobileOperatorInfoCarriersUsCellularTest, RoamOutsideTheUs) {
  std::vector<string> serving_mccmncs;
  // US MCC is "31[0-6]...". Add random MCCMNCs that don't match that prefix.
  // Add upper boundary MCCMNC
  serving_mccmncs.push_back("317000");
  while (serving_mccmncs.size() < 10) {
    std::string mccmnc = CreateRandomMccmnc("", 5);
    if (!base::StartsWith(mccmnc, "31"))
      serving_mccmncs.push_back(mccmnc);
  }
  while (serving_mccmncs.size() < 20) {
    std::string mccmnc = CreateRandomMccmnc("", 6);
    if (!base::StartsWith(mccmnc, "31"))
      serving_mccmncs.push_back(mccmnc);
  }

  for (const auto& serving_mccmnc : serving_mccmncs) {
    for (const auto& mccmnc : kUsCellularMccmncs) {
      operator_info_->UpdateMCCMNC(mccmnc);
      operator_info_->UpdateServingMCCMNC(serving_mccmnc);
      EXPECT_EQ(operator_info_->operator_name(), kUsCellularOperatorName);
      EXPECT_EQ(operator_info_->requires_roaming(), false)
          << " serving_mccmnc: " << serving_mccmnc;
      CheckFirstApn(kUsCellularApn);
    }
  }
}

class MobileOperatorInfoCarriersRogersTest
    : public MobileOperatorInfoCarriersTest {
 public:
  MobileOperatorInfoCarriersRogersTest()
      : kRogersApn4G(ApnBuilder("ltemobile.apn")
                         .IpType(kApnIpTypeV4V6)
                         .ApnTypes({kApnTypeDefault})),
        kRogersApn4GDun(ApnBuilder("ltedata.apn")
                            .IpType(kApnIpTypeV4V6)
                            .ApnTypes({kApnTypeDun})
                            .IsRequiredByCarrierSpec(true)),
        kRogersApn5G(ApnBuilder("mobile.apn")
                         .IpType(kApnIpTypeV4V6)
                         .ApnTypes({kApnTypeDefault})),
        kRogersApn5GDun(ApnBuilder("data.apn")
                            .IpType(kApnIpTypeV4V6)
                            .ApnTypes({kApnTypeDun})
                            .IsRequiredByCarrierSpec(true)),
        kRogersMccmncs({"302720"}) {}

 protected:
  const ApnBuilder kRogersApn4G;
  const ApnBuilder kRogersApn4GDun;
  const ApnBuilder kRogersApn5G;
  const ApnBuilder kRogersApn5GDun;

  const std::set<string> kRogersMccmncs;

  static constexpr char kRogersOperatorName[] = "Rogers";
};

TEST_F(MobileOperatorInfoCarriersRogersTest, RogersHome_RogersServing) {
  for (const auto& home : kRogersMccmncs) {
    operator_info_->UpdateMCCMNC(home);
    operator_info_->UpdateServingMCCMNC(home);
    operator_info_->UpdateGID1("FF");
    EXPECT_EQ(operator_info_->operator_name(), kRogersOperatorName);
    EXPECT_EQ(operator_info_->serving_operator_name(), kRogersOperatorName);
    CheckFirstApn(kRogersApn4G);
    CheckIfApnExists(kRogersApn4GDun);
  }
}

TEST_F(MobileOperatorInfoCarriersRogersTest, UnknownHome_RogersServing) {
  for (const auto& home : kRogersMccmncs) {
    operator_info_->UpdateMCCMNC(kUnknownMccmnc);
    operator_info_->UpdateServingMCCMNC(home);
    operator_info_->UpdateGID1("FF");
    EXPECT_EQ(operator_info_->operator_name(), "");
    EXPECT_EQ(operator_info_->serving_operator_name(), kRogersOperatorName);
    EXPECT_EQ(operator_info_->apn_list().size(), 0);
  }
}

TEST_F(MobileOperatorInfoCarriersRogersTest, Rogers5gHome_RogersServing) {
  for (const auto& home : kRogersMccmncs) {
    operator_info_->UpdateMCCMNC(home);
    operator_info_->UpdateServingMCCMNC(home);
    // Rogers 5G has a GID1 filter
    operator_info_->UpdateGID1("A4");
    EXPECT_EQ(operator_info_->operator_name(), kRogersOperatorName);
    EXPECT_EQ(operator_info_->serving_operator_name(), kRogersOperatorName);
    CheckFirstApn(kRogersApn5G);
    CheckIfApnExists(kRogersApn4G);
    CheckIfApnExists(kRogersApn5GDun);
    CheckIfApnExists(kRogersApn4GDun);
  }
}

TEST_F(MobileOperatorInfoCarriersRogersTest, Unknown5gHome_RogersServing) {
  for (const auto& home : kRogersMccmncs) {
    operator_info_->UpdateMCCMNC(kUnknownMccmnc);
    operator_info_->UpdateServingMCCMNC(home);
    // Rogers 5G has a GID1 filter
    operator_info_->UpdateGID1("A4");
    EXPECT_EQ(operator_info_->operator_name(), "");
    EXPECT_EQ(operator_info_->serving_operator_name(), kRogersOperatorName);
    EXPECT_EQ(operator_info_->apn_list().size(), 0);
  }
}
}  // namespace shill
