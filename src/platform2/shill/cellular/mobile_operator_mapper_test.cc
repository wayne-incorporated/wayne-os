// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_mapper.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/test/mock_callback.h>
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/cellular/apn_list.h"
#include "shill/cellular/mobile_operator_storage.h"
#include "shill/logging.h"
#include "shill/test_event_dispatcher.h"

using testing::Mock;
using testing::StrictMock;
using testing::Test;
using testing::Values;
using testing::WithParamInterface;

// The tests run from the fixture |MobileOperatorMapperMainTest| and
// |MobileOperatorMapperDataTest| can be run in two modes:
//   - strict event checking: We check that an event is raised for each update
//     to the state of the object.
//   - non-strict event checking: We check that a single event is raised as a
//     result of many updates to the object.
// The first case corresponds to a very aggressive event loop, that dispatches
// events as soon as they are posted; the second one corresponds to an
// over-crowded event loop that only dispatches events just before we verify
// that events were raised.
//
// We use ::testing::WithParamInterface to templatize the test fixtures to do
// string/non-strict event checking. When writing test cases using these
// fixtures, use the |Update*|, |ExpectEventCount|, |VerifyEventCount| functions
// provided by the fixture, and write the test as if event checking is strict.
//
// For |MobileOperatorObserverTest|, only the strict event checking case makes
// sense, so we only instantiate that.
namespace shill {

namespace {

enum EventCheckingPolicy {
  kEventCheckingPolicyStrict,
  kEventCheckingPolicyNonStrict
};

base::FilePath GetTestProtoPath(const std::string& file) {
  const char* out_dir = getenv("OUT");
  CHECK_NE(out_dir, nullptr);
  return base::FilePath(out_dir).Append(file);
}

}  // namespace

using MobileOperatorMapperOnOperatorChangedCallbackMock =
    base::MockRepeatingCallback<void()>;

class MobileOperatorMapperInitTest : public Test {
 public:
  MobileOperatorMapperInitTest()
      : operator_info_(new MobileOperatorMapper(&dispatcher_, "Operator")) {}
  MobileOperatorMapperInitTest(const MobileOperatorMapperInitTest&) = delete;
  MobileOperatorMapperInitTest& operator=(const MobileOperatorMapperInitTest&) =
      delete;

 protected:
  bool SetUpDatabase(const std::vector<std::string>& files) {
    operator_info_->ClearDatabasePaths();
    for (const auto& file : files) {
      operator_info_->AddDatabasePath(GetTestProtoPath(file));
    }
    return operator_info_->Init(on_operator_changed_cb_.Get());
  }

  void SetUp() override {
    shill::ScopeLogger::GetInstance()->set_verbose_level(0);
    shill::ScopeLogger::GetInstance()->EnableScopesByName("cellular");
  }

  void AssertDatabaseEmpty() {
    EXPECT_EQ(0, operator_info_->databases()[0]->mno_size());
    EXPECT_EQ(0, operator_info_->databases()[0]->mvno_size());
  }

  const std::vector<const shill::mobile_operator_db::MobileOperatorDB*>
  GetDatabases() {
    return operator_info_->databases();
  }

  EventDispatcherForTest dispatcher_;
  std::unique_ptr<MobileOperatorMapper> operator_info_;
  MobileOperatorMapperOnOperatorChangedCallbackMock on_operator_changed_cb_;
};

TEST_F(MobileOperatorMapperInitTest, FailedInitNoPath) {
  // - Initialize object with no database paths set
  // - Verify that initialization fails.
  operator_info_->ClearDatabasePaths();
  MobileOperatorStorage::GetInstance()->ClearDatabases();
  EXPECT_FALSE(operator_info_->Init(on_operator_changed_cb_.Get()));
  EXPECT_TRUE(GetDatabases().empty());
}

TEST_F(MobileOperatorMapperInitTest, FailedInitBadPath) {
  // - Initialize object with non-existent path.
  // - Verify that initialization fails.
  EXPECT_FALSE(SetUpDatabase({"nonexistent.pbf"}));
  EXPECT_TRUE(GetDatabases().empty());
}

TEST_F(MobileOperatorMapperInitTest, FailedInitBadDatabase) {
  // - Initialize object with malformed database.
  // - Verify that initialization fails.
  // TODO(pprabhu): It's hard to get a malformed database in binary format.
}

TEST_F(MobileOperatorMapperInitTest, EmptyDBInit) {
  // - Initialize the object with a database file that is empty.
  // - Verify that initialization succeeds, and that the database is empty.
  EXPECT_TRUE(SetUpDatabase({"init_test_empty_db_init.pbf"}));
  AssertDatabaseEmpty();
}

TEST_F(MobileOperatorMapperInitTest, SuccessfulInit) {
  EXPECT_TRUE(SetUpDatabase({"init_test_successful_init.pbf"}));
  EXPECT_GT(GetDatabases()[0]->mno_size(), 0);
  EXPECT_GT(GetDatabases()[0]->mvno_size(), 0);
}

TEST_F(MobileOperatorMapperInitTest, MultipleDBInit) {
  // - Initialize the object with two database files.
  // - Verify that initialization succeeds, and both databases are loaded.
  EXPECT_TRUE(SetUpDatabase({"init_test_multiple_db_init_1.pbf",
                             "init_test_multiple_db_init_2.pbf"}));
  EXPECT_TRUE(operator_info_->Init(on_operator_changed_cb_.Get()));
  EXPECT_GT(GetDatabases()[0]->mno_size(), 0);
  EXPECT_GT(GetDatabases()[1]->mno_size(), 0);
  EXPECT_EQ(operator_info_->uuid(), "");
  operator_info_->UpdateMCCMNC("999001");
  EXPECT_EQ(operator_info_->uuid(), "muahahahaha");
  operator_info_->UpdateMCCMNC("999002");
  EXPECT_EQ(operator_info_->uuid(), "teeheehee");
}

class MobileOperatorMapperMainTest
    : public MobileOperatorMapperInitTest,
      public WithParamInterface<EventCheckingPolicy> {
 public:
  MobileOperatorMapperMainTest() : event_checking_policy_(GetParam()) {}
  MobileOperatorMapperMainTest(const MobileOperatorMapperMainTest&) = delete;
  MobileOperatorMapperMainTest& operator=(const MobileOperatorMapperMainTest&) =
      delete;

  void SetUp() override { EXPECT_TRUE(SetUpDatabase({"main_test.pbf"})); }

 protected:
  // ///////////////////////////////////////////////////////////////////////////
  // Helper functions.
  void VerifyMNOWithUUID(const std::string& uuid) {
    EXPECT_TRUE(operator_info_->IsMobileNetworkOperatorKnown());
    EXPECT_FALSE(operator_info_->IsMobileVirtualNetworkOperatorKnown());
    EXPECT_EQ(uuid, operator_info_->uuid());
  }

  void VerifyMVNOWithUUID(const std::string& uuid) {
    EXPECT_TRUE(operator_info_->IsMobileNetworkOperatorKnown());
    EXPECT_TRUE(operator_info_->IsMobileVirtualNetworkOperatorKnown());
    EXPECT_EQ(uuid, operator_info_->uuid());
  }

  void VerifyNoMatch() {
    EXPECT_FALSE(operator_info_->IsMobileNetworkOperatorKnown());
    EXPECT_FALSE(operator_info_->IsMobileVirtualNetworkOperatorKnown());
    EXPECT_EQ("", operator_info_->uuid());
  }

  void ExpectEventCount(int count) {
    // In case we're running in the non-strict event checking mode, we only
    // expect one overall event to be raised for all the updates.
    if (event_checking_policy_ == kEventCheckingPolicyNonStrict) {
      count = (count > 0) ? 1 : 0;
    }
    EXPECT_CALL(on_operator_changed_cb_, Run()).Times(count);
  }

  void VerifyEventCount() {
    dispatcher_.DispatchPendingEvents();
    Mock::VerifyAndClearExpectations(&on_operator_changed_cb_);
  }

  void ResetOperatorInfo() {
    operator_info_->Reset();
    // Eat up any events caused by |Reset|.
    dispatcher_.DispatchPendingEvents();
    VerifyNoMatch();
  }

  // Use these wrappers to send updates to |operator_info_|. These wrappers
  // optionally run the dispatcher if we want strict checking of the number of
  // events raised.
  void UpdateMCCMNC(const std::string& mccmnc) {
    operator_info_->UpdateMCCMNC(mccmnc);
    DispatchPendingEventsIfStrict();
  }

  void UpdateIMSI(const std::string& imsi) {
    operator_info_->UpdateIMSI(imsi);
    DispatchPendingEventsIfStrict();
  }

  void UpdateICCID(const std::string& iccid) {
    operator_info_->UpdateICCID(iccid);
    DispatchPendingEventsIfStrict();
  }

  void UpdateOperatorName(const std::string& operator_name) {
    operator_info_->UpdateOperatorName(operator_name);
    DispatchPendingEventsIfStrict();
  }

  void UpdateGID1(const std::string& gid1) {
    operator_info_->UpdateGID1(gid1);
    DispatchPendingEventsIfStrict();
  }

  void UpdateOnlinePortal(const std::string& url,
                          const std::string& method,
                          const std::string& post_data) {
    operator_info_->UpdateOnlinePortal(url, method, post_data);
    DispatchPendingEventsIfStrict();
  }

  void DispatchPendingEventsIfStrict() {
    if (event_checking_policy_ == kEventCheckingPolicyStrict) {
      dispatcher_.DispatchPendingEvents();
    }
  }

  // ///////////////////////////////////////////////////////////////////////////
  // Data.
  const EventCheckingPolicy event_checking_policy_;
};

TEST_P(MobileOperatorMapperMainTest, InitialConditions) {
  // - Initialize a new object.
  // - Verify that all initial values of properties are reasonable.
  EXPECT_FALSE(operator_info_->IsMobileNetworkOperatorKnown());
  EXPECT_FALSE(operator_info_->IsMobileVirtualNetworkOperatorKnown());
  EXPECT_TRUE(operator_info_->uuid().empty());
  EXPECT_TRUE(operator_info_->operator_name().empty());
  EXPECT_TRUE(operator_info_->country().empty());
  EXPECT_TRUE(operator_info_->mccmnc().empty());
  EXPECT_TRUE(operator_info_->mccmnc_list().empty());
  EXPECT_TRUE(operator_info_->operator_name_list().empty());
  EXPECT_TRUE(operator_info_->apn_list().empty());
  EXPECT_TRUE(operator_info_->olp_list().empty());
  EXPECT_FALSE(operator_info_->requires_roaming());
  EXPECT_FALSE(operator_info_->tethering_allowed());
  EXPECT_FALSE(operator_info_->use_dun_apn_as_default());
  EXPECT_EQ(0, operator_info_->mtu());
  EXPECT_TRUE(operator_info_->entitlement_config().url.empty());
  EXPECT_TRUE(operator_info_->entitlement_config().method.empty());
  EXPECT_TRUE(operator_info_->entitlement_config().params.empty());
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNC) {
  // message: Has an MNO with no MVNO.
  // match by: MCCMNC.
  // verify: Callback event, uuid.

  ExpectEventCount(0);
  UpdateMCCMNC("101999");  // No match.
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(1);
  UpdateMCCMNC("101001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid101");

  ExpectEventCount(1);
  UpdateMCCMNC("101999");
  VerifyEventCount();
  VerifyNoMatch();
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNCMultipleMCCMNCOptions) {
  // message: Has an MNO with no MCCMNC.
  // match by: One of the MCCMNCs of the multiple ones in the MNO.
  // verify: Callback event, uuid.
  ExpectEventCount(1);
  UpdateMCCMNC("102002");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid102");
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNCMultipleMNOOptions) {
  // message: Two messages with the same MCCMNC.
  // match by: Both MNOs matched, one is earmarked.
  // verify: The earmarked MNO is picked.
  ExpectEventCount(1);
  UpdateMCCMNC("124001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid124002");
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorName) {
  // message: Has an MNO with no MVNO.
  // match by: OperatorName.
  // verify: Callback event, uuid.
  ExpectEventCount(0);
  UpdateOperatorName("name103999");  // No match.
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(1);
  UpdateOperatorName("name103");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid103");

  ExpectEventCount(1);
  UpdateOperatorName("name103999");  // No match.
  VerifyEventCount();
  VerifyNoMatch();
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorNameMultipleMNOOptions) {
  // message: Two messages with the same operator name.
  // match by: Both MNOs matched, one is earmarked.
  // verify: The earmarked MNO is picked.
  ExpectEventCount(1);
  UpdateOperatorName("name125001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid125002");
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorNameAggressiveMatch) {
  // These network operators match by name but only after normalizing the names.
  // Both the name from the database and the name provided to
  // |UpdateOperatorName| must be normalized for this test to pass.
  ExpectEventCount(1);
  UpdateOperatorName("name126001 casedoesnotmatch");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid126001");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateOperatorName("name126002 CaseStillDoesNotMatch");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid126002");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateOperatorName("name126003GiveMeMoreSpace");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid126003");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateOperatorName("name126004  Too  Much   Air Here");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid126004");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateOperatorName("näméwithNon-Äσ¢ii");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid126005");
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorNameWithLang) {
  // message: Has an MNO with no MVNO.
  // match by: OperatorName.
  // verify: Callback event, fields.
  ExpectEventCount(1);
  UpdateOperatorName("name105");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid105");
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorNameMultipleNameOptions) {
  // message: Has an MNO with no MVNO.
  // match by: OperatorName, one of the multiple present in the MNO.
  // verify: Callback event, fields.
  ExpectEventCount(1);
  UpdateOperatorName("name104002");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid104");
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNCAndOperatorName) {
  // message: Has MNOs with no MVNO.
  // match by: MCCMNC finds two candidates (first one is chosen), Name narrows
  //           down to one.
  // verify: Callback event, fields.
  // This is merely a MCCMNC update.
  ExpectEventCount(1);
  UpdateMCCMNC("106001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid106001");

  ExpectEventCount(1);
  UpdateOperatorName("name106002");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid106002");

  ResetOperatorInfo();
  // Try updates in reverse order.
  ExpectEventCount(1);
  UpdateOperatorName("name106001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid106001");
}

TEST_P(MobileOperatorMapperMainTest, MNOByOperatorNameAndMCCMNC) {
  // message: Has MNOs with no MVNO.
  // match by: OperatorName finds two (first one is chosen), MCCMNC narrows down
  //           to one.
  // verify: Callback event, fields.
  // This is merely an OperatorName update.
  ExpectEventCount(1);
  UpdateOperatorName("name107");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid107001");

  ExpectEventCount(1);
  UpdateMCCMNC("107002");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid107002");

  ResetOperatorInfo();
  // Try updates in reverse order.
  ExpectEventCount(1);
  UpdateMCCMNC("107001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid107001");
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNCOverridesOperatorName) {
  // message: Has MNOs with no MVNO.
  // match by: First MCCMNC finds one. Then, OperatorName matches another.
  // verify: MCCMNC match prevails. No change on OperatorName update.
  ExpectEventCount(1);
  UpdateMCCMNC("108001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid108001");

  // An event is sent for the updated OperatorName.
  ExpectEventCount(1);
  UpdateOperatorName("name108002");  // Does not match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid108001");
  // OperatorName will display the user supplied operator, but this shouldn't
  // change the operator.
  EXPECT_EQ("name108002", operator_info_->operator_name());

  ResetOperatorInfo();
  // message: Same as above.
  // match by: First OperatorName finds one, then MCCMNC overrides it.
  // verify: Two events, MCCMNC one overriding the OperatorName one.
  ExpectEventCount(1);
  UpdateOperatorName("name108001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid108001");

  ExpectEventCount(1);
  UpdateMCCMNC("108002");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid108002");
  // But we still show the user supplied operator.
  EXPECT_EQ("name108001", operator_info_->operator_name());

  // message: Same as above.
  // match by: First a *wrong* MCCMNC update, followed by the correct Name
  // update.
  // verify: No MNO, since MCCMNC is given precedence.
  ResetOperatorInfo();
  ExpectEventCount(0);
  UpdateMCCMNC("108999");  // Does not match.
  UpdateOperatorName("name108001");
  VerifyEventCount();
  VerifyNoMatch();
}

TEST_P(MobileOperatorMapperMainTest, MNOByIMSI) {
  // message: Has MNO with no MVNO.
  // match by: MCCMNC part of IMSI of length 5 / 6.
  ExpectEventCount(0);
  UpdateIMSI("109");  // Too short.
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(0);
  UpdateIMSI("109995432154321");  // No match.
  VerifyEventCount();
  VerifyNoMatch();

  ResetOperatorInfo();
  // Short MCCMNC match.
  ExpectEventCount(1);
  UpdateIMSI("109015432154321");  // First 5 digits match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid10901");

  ResetOperatorInfo();
  // Long MCCMNC match.
  ExpectEventCount(1);
  UpdateIMSI("10900215432154321");  // First 6 digits match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid109002");
}

TEST_P(MobileOperatorMapperMainTest, MNOByMCCMNCOverridesIMSI) {
  // message: Has MNOs with no MVNO.
  // match by: One matches MCCMNC, then one matches a different MCCMNC substring
  //    of IMSI
  // verify: Callback event for the first match, all fields. Second Update
  // ignored.
  ExpectEventCount(1);
  UpdateMCCMNC("110001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110001");

  // MNO remains unchanged on a mismatched IMSI update.
  ExpectEventCount(0);
  UpdateIMSI("1100025432154321");  // First 6 digits match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110001");

  // MNO remains unchanged on an invalid IMSI update.
  ExpectEventCount(0);
  UpdateIMSI("1100035432154321");  // Prefix does not match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110001");

  ExpectEventCount(0);
  UpdateIMSI("110");  // Too small.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110001");

  ResetOperatorInfo();
  // Same as above, but this time, match with IMSI, followed by a contradictory
  // MCCMNC update. The second update should override the first one.
  ExpectEventCount(1);
  UpdateIMSI("1100025432154321");  // First 6 digits match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110002");

  ExpectEventCount(1);
  UpdateMCCMNC("110001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid110001");
}

TEST_P(MobileOperatorMapperMainTest, MNORoamingFilterMCCMNCMatch) {
  // This test verifies that the network is identified as Home when roaming on
  // a carrier that matches the roaming filter.
  // message: MNO with a roaming_filter.
  // match by: Serving operator MCCMNC.
  MobileOperatorMapper serving_operator_info(&dispatcher_, "Serving");
  MobileOperatorMapperOnOperatorChangedCallbackMock cb;
  serving_operator_info.Init(cb.Get());
  ExpectEventCount(1);
  UpdateMCCMNC("129001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid129001");
  serving_operator_info.UpdateMCCMNC("128001");  // matches "128[0-6]..?"
  EXPECT_TRUE(
      operator_info_->RequiresRoamingOnOperator(&serving_operator_info));

  serving_operator_info.UpdateMCCMNC("127001");  // no match
  EXPECT_FALSE(
      operator_info_->RequiresRoamingOnOperator(&serving_operator_info));
}

TEST_P(MobileOperatorMapperMainTest, MVNODefaultMatch) {
  // message: MNO with one MVNO (no filter).
  // match by: MNO matches by MCCMNC.
  // verify: Callback event for MVNO match. Uuid match the MVNO.
  // second update: ICCID.
  // verify: No callback event, match remains unchanged.
  ExpectEventCount(1);
  UpdateMCCMNC("112001");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid112002");

  ExpectEventCount(0);
  UpdateICCID("112002");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid112002");
}

TEST_P(MobileOperatorMapperMainTest, MVNONameMatch) {
  // message: MNO with one MVNO (name filter).
  // match by: MNO matches by MCCMNC,
  //           MVNO fails to match by fist name update,
  //           then MVNO matches by name.
  // verify: Two callback events: MNO followed by MVNO.
  ExpectEventCount(1);
  UpdateMCCMNC("113001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid113001");

  ExpectEventCount(1);
  UpdateOperatorName("name113999");  // No match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid113001");
  // User supplied name is still given preference.
  EXPECT_EQ("name113999", operator_info_->operator_name());

  ExpectEventCount(1);
  UpdateOperatorName("name113002");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid113002");
  EXPECT_EQ("name113002", operator_info_->operator_name());
}

TEST_P(MobileOperatorMapperMainTest, MVNONameMalformedRegexMatch) {
  // message: MNO with one MVNO (name filter with a malformed regex).
  // match by: MNO matches by MCCMNC.
  //           MVNO does not match
  ExpectEventCount(2);
  UpdateMCCMNC("114001");
  UpdateOperatorName("name[");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid114001");
}

TEST_P(MobileOperatorMapperMainTest, MVNONameSubexpressionRegexMatch) {
  // message: MNO with one MVNO (name filter with simple regex).
  // match by: MNO matches by MCCMNC.
  //           MVNO does not match with a name whose subexpression matches the
  //           regex.
  ExpectEventCount(2);  // One event for just the name update.
  UpdateMCCMNC("115001");
  UpdateOperatorName("name115_ExtraCrud");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid115001");

  ResetOperatorInfo();
  ExpectEventCount(2);  // One event for just the name update.
  UpdateMCCMNC("115001");
  UpdateOperatorName("ExtraCrud_name115");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid115001");

  ResetOperatorInfo();
  ExpectEventCount(2);  // One event for just the name update.
  UpdateMCCMNC("115001");
  UpdateOperatorName("ExtraCrud_name115_ExtraCrud");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid115001");

  ResetOperatorInfo();
  ExpectEventCount(2);  // One event for just the name update.
  UpdateMCCMNC("115001");
  UpdateOperatorName("name_ExtraCrud_115");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid115001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("115001");
  UpdateOperatorName("name115");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid115002");
}

TEST_P(MobileOperatorMapperMainTest, MVNONameRegexMatch) {
  // message: MNO with one MVNO (name filter with non-trivial regex).
  // match by: MNO matches by MCCMNC.
  //           MVNO fails to match several times with different strings.
  //           MVNO matches several times with different values.

  // Make sure we're not taking the regex literally!
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("name[a-zA-Z_]*116[0-9]{0,3}");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid116001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("name[a-zA-Z_]116[0-9]");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid116001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("nameb*1167");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid116001");

  // Success!
  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("name116");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid116002");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("nameSomeWord116");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid116002");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("116001");
  UpdateOperatorName("name116567");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid116002");
}

TEST_P(MobileOperatorMapperMainTest, MVNONameMatchMultipleFilters) {
  // message: MNO with one MVNO with two name filters.
  // match by: MNO matches by MCCMNC.
  //           MVNO first fails on the second filter alone.
  //           MVNO fails on the first filter alone.
  //           MVNO matches on both filters.
  ExpectEventCount(2);
  UpdateMCCMNC("117001");
  UpdateOperatorName("nameA_crud");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid117001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("117001");
  UpdateOperatorName("crud_nameB");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid117001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("117001");
  UpdateOperatorName("crud_crud");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid117001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("117001");
  UpdateOperatorName("nameA_nameB");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid117002");
}

TEST_P(MobileOperatorMapperMainTest, MVNOIMSIMatch) {
  // message: MNO with one MVNO (imsi filter).
  // match by: MNO matches by MCCMNC,
  //           MVNO fails to match by fist imsi update,
  //           then MVNO matches by imsi.
  // verify: Two Callback events: MNO followed by MVNO.
  //         the MVNO database operator name has higher priority
  //         than the MNO name returned by the SIM.
  ExpectEventCount(2);
  UpdateMCCMNC("118001");
  UpdateOperatorName("MNO_random_name");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid118001");

  ExpectEventCount(0);
  UpdateIMSI("1180011234512345");  // No match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid118001");
  EXPECT_EQ("MNO_random_name", operator_info_->operator_name());

  ExpectEventCount(1);
  UpdateIMSI("1180015432154321");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid118002");
  EXPECT_EQ("name118002", operator_info_->operator_name());
}

TEST_P(MobileOperatorMapperMainTest, MVNOIMSIMatchByRange) {
  // message: MNO with one MVNO (IMSI filter with 2 numerical ranges).
  // match by: MNO matches by MCCMNC,
  //           MVNO fails to match by first IMSI update,
  //           then MVNO matches in the first IMSI,
  //           then alternately put IMSI inside and outside the ranges.
  // verify: Callback events: alternately MNO when no match,
  //                          then MVNO when match.
  ExpectEventCount(1);
  UpdateMCCMNC("128001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid128001");

  ExpectEventCount(0);
  UpdateIMSI("128001234512345");  // No match before 1st range
  VerifyEventCount();
  VerifyMNOWithUUID("uuid128001");

  ExpectEventCount(1);
  UpdateIMSI("128001432159321");  // Match, middle of 1st range
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid128002");

  ExpectEventCount(1);
  UpdateIMSI("128001435124321");  // No match between ranges
  VerifyEventCount();
  VerifyMNOWithUUID("uuid128001");

  ExpectEventCount(1);
  UpdateIMSI("128001438055555");  // Match, middle of 2nd range
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid128002");

  ExpectEventCount(1);
  UpdateIMSI("128001432154320");  // No match 1 before 1st range
  VerifyEventCount();
  VerifyMNOWithUUID("uuid128001");

  ExpectEventCount(1);
  UpdateIMSI("128001437999999");  // Match, first of 2nd range
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid128002");

  ExpectEventCount(1);
  UpdateIMSI("128001432164322");  // No match 1 after 1st range
  VerifyEventCount();
  VerifyMNOWithUUID("uuid128001");

  ExpectEventCount(1);
  UpdateIMSI("128001438111111");  // Match, last of 2nd range
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid128002");
}

TEST_P(MobileOperatorMapperMainTest, MVNOICCIDMatch) {
  // message: MNO with one MVNO (iccid filter).
  // match by: MNO matches by MCCMNC,
  //           MVNO fails to match by fist iccid update,
  //           then MVNO matches by iccid.
  // verify: Two Callback events: MNO followed by MVNO.
  ExpectEventCount(1);
  UpdateMCCMNC("119001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid119001");

  ExpectEventCount(0);
  UpdateICCID("119987654321");  // No match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid119001");

  ExpectEventCount(1);
  UpdateICCID("119123456789");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid119002");
}

TEST_P(MobileOperatorMapperMainTest, InternationalMVNOMatch) {
  // message: international MVNO (imsi filter).
  // match by: MNO matches by MCCMNC,
  //           MVNO matches by IMSI after first IMSI update,
  //           MVNO matches again after MCCMNC change.
  // verify: Three Callback events: MNO followed by MVNO twice.
  ExpectEventCount(1);
  UpdateMCCMNC("127001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid127001");

  ExpectEventCount(1);
  UpdateIMSI("1270015432154322");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid127001-mvno");

  ExpectEventCount(1);
  UpdateMCCMNC("118001");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid127001-mvno");
}

TEST_P(MobileOperatorMapperMainTest, MVNOAllMatch) {
  // message: MNO with following MVNOS:
  //   - one with no filter.
  //   - one with name filter.
  //   - one with imsi filter.
  //   - one with iccid filter.
  //   - one with name and iccid filter.
  // verify:
  //   - initial MCCMNC matches the default MVNO directly (not MNO)
  //   - match each of the MVNOs in turn.
  //   - give super set information that does not match any MVNO correctly,
  //     verify that the MNO matches.
  ExpectEventCount(1);
  UpdateMCCMNC("121001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid121001");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("121001");
  UpdateOperatorName("name121003");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid121003");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("121001");
  UpdateIMSI("1210045432154321");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid121004");

  ResetOperatorInfo();
  ExpectEventCount(2);
  UpdateMCCMNC("121001");
  UpdateICCID("121005123456789");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid121005");

  ResetOperatorInfo();
  ExpectEventCount(3);
  UpdateMCCMNC("121001");
  UpdateOperatorName("name121006");
  VerifyMNOWithUUID("uuid121001");
  UpdateICCID("121006123456789");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid121006");
}

TEST_P(MobileOperatorMapperMainTest, MVNOMatchAndMismatch) {
  // message: MNO with one MVNO with name filter.
  // match by: MNO matches by MCCMNC
  //           MVNO matches by name.
  //           Second name update causes the MVNO to not match again.
  ExpectEventCount(1);
  UpdateMCCMNC("113001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid113001");

  ExpectEventCount(1);
  UpdateOperatorName("name113002");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid113002");
  EXPECT_EQ("name113002", operator_info_->operator_name());

  ExpectEventCount(1);
  UpdateOperatorName("name113999");  // No match.
  VerifyEventCount();
  VerifyMNOWithUUID("uuid113001");
  // User operator name is given preference.
  EXPECT_EQ("name113999", operator_info_->operator_name());
}

TEST_P(MobileOperatorMapperMainTest, MVNOMatchAndReset) {
  // message: MVNO with name filter.
  // verify;
  //   - match MVNO by name.
  //   - Reset object, verify Callback event, and not match.
  //   - match MVNO by name again.
  ExpectEventCount(1);
  UpdateMCCMNC("113001");
  VerifyEventCount();
  ExpectEventCount(1);
  VerifyMNOWithUUID("uuid113001");
  UpdateOperatorName("name113002");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid113002");
  EXPECT_EQ("name113002", operator_info_->operator_name());

  ExpectEventCount(1);
  operator_info_->Reset();
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(1);
  UpdateMCCMNC("113001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid113001");
  ExpectEventCount(1);
  UpdateOperatorName("name113002");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid113002");
  EXPECT_EQ("name113002", operator_info_->operator_name());
}

TEST_P(MobileOperatorMapperMainTest, APNFilter) {
  // This test verifies that APNs can be filtered
  // message: MNO with a apn_filters.
  // match by: IMSI.
  ExpectEventCount(1);
  UpdateMCCMNC("130001");
  UpdateIMSI("130001123456789");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid130001");
  ASSERT_EQ(operator_info_->apn_list().size(), 2);
  EXPECT_STREQ(operator_info_->apn_list()[0].apn.c_str(), "apn_regex");
  EXPECT_STREQ(operator_info_->apn_list()[1].apn.c_str(), "apn_exclude_regex");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateMCCMNC("130001");
  UpdateIMSI("130001110000000");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid130001");
  ASSERT_EQ(operator_info_->apn_list().size(), 1);
  EXPECT_STREQ(operator_info_->apn_list()[0].apn.c_str(), "apn_exclude_regex");

  ResetOperatorInfo();
  ExpectEventCount(1);
  UpdateMCCMNC("130001");
  UpdateIMSI("130001323456789");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid130001");
  ASSERT_EQ(operator_info_->apn_list().size(), 1);
  EXPECT_STREQ(operator_info_->apn_list()[0].apn.c_str(), "apn_regex");
}

class MobileOperatorMapperDataTest : public MobileOperatorMapperMainTest {
 public:
  MobileOperatorMapperDataTest() = default;
  MobileOperatorMapperDataTest(const MobileOperatorMapperDataTest&) = delete;
  MobileOperatorMapperDataTest& operator=(const MobileOperatorMapperDataTest&) =
      delete;

  // Same as MobileOperatorMapperMainTest, except that the database used is
  // different.
  void SetUp() override { EXPECT_TRUE(SetUpDatabase({"data_test.pbf"})); }

 protected:
  // This is a function that does a best effort verification of the information
  // that is obtained from the database by the MobileOperatorMapper object
  // against expectations stored in the form of data members in this class. This
  // is not a full proof check. In particular:
  //  - It is unspecified in some case which of the values from a list is
  //    exposed as a property.
  //  - It is not robust to use "" as property values at times.
  void VerifyDatabaseData() {
    EXPECT_EQ(country_, operator_info_->country());
    EXPECT_EQ(requires_roaming_, operator_info_->requires_roaming());
    EXPECT_EQ(mtu_, operator_info_->mtu());

    EXPECT_EQ(mccmnc_list_.size(), operator_info_->mccmnc_list().size());
    std::set<std::string> mccmnc_set(operator_info_->mccmnc_list().begin(),
                                     operator_info_->mccmnc_list().end());
    for (const auto& mccmnc : mccmnc_list_) {
      EXPECT_TRUE(mccmnc_set.find(mccmnc) != mccmnc_set.end());
    }
    if (!mccmnc_list_.empty()) {
      // It is not specified which entry will be chosen, but mccmnc() must be
      // non empty.
      EXPECT_FALSE(operator_info_->mccmnc().empty());
    }

    // 2 |operator_name_list| cannot be compared with equality because
    // |UpdateOperatorName| only adds the operator name, and not the language.
    VerifyNameListsMatch(operator_name_list_,
                         operator_info_->operator_name_list());
    EXPECT_EQ(apn_list_, operator_info_->apn_list())
        << " apn_list_:" << ApnsToString(apn_list_)
        << " \noperator_info_->apn_list():"
        << ApnsToString(operator_info_->apn_list());
    EXPECT_EQ(olp_list_, operator_info_->olp_list());
  }

  std::string ApnsToString(std::vector<MobileOperatorMapper::MobileAPN> apns) {
    std::vector<std::string> apn_strings;
    for (const auto& apn : apns) {
      apn_strings.push_back(ApnToString(apn));
    }
    return base::JoinString(apn_strings, ",");
  }

  std::string ApnToString(MobileOperatorMapper::MobileAPN apn) {
    return base::StringPrintf(
        "{apn: %s, username: %s, password: %s, authentication: %s, ip_type: %s "
        ", apn_types: %s , operator_name_list.size(): %s, "
        "is_required_by_carrier_spec: %d}",
        apn.apn.c_str(), apn.username.c_str(), apn.password.c_str(),
        apn.authentication.c_str(), apn.ip_type.c_str(),
        ApnList::JoinApnTypes(std::vector<std::string>(apn.apn_types.begin(),
                                                       apn.apn_types.end()))
            .c_str(),
        base::NumberToString(apn.operator_name_list.size()).c_str(),
        apn.is_required_by_carrier_spec);
  }

  void VerifyNonInheritableDatabaseDataMNO(std::string imsi) {
    EXPECT_EQ(tethering_allowed_, operator_info_->tethering_allowed());
    EXPECT_EQ(use_dun_apn_as_default_,
              operator_info_->use_dun_apn_as_default());
    static const Stringmap mhs_entitlement_params = {{"imsi", imsi}};
    EXPECT_EQ("uuid200001.com", operator_info_->entitlement_config().url);
    EXPECT_EQ("GET", operator_info_->entitlement_config().method);
    EXPECT_EQ(mhs_entitlement_params,
              operator_info_->entitlement_config().params);
  }

  void VerifyNonInheritableDatabaseDataMVNO() {
    EXPECT_EQ(tethering_allowed_, operator_info_->tethering_allowed());
    EXPECT_EQ(use_dun_apn_as_default_,
              operator_info_->use_dun_apn_as_default());
    EXPECT_EQ("uuid200101.com", operator_info_->entitlement_config().url);
    EXPECT_EQ("POST", operator_info_->entitlement_config().method);
    EXPECT_TRUE(operator_info_->entitlement_config().params.empty());
  }
  void VerifyNonInheritableDatabaseDataEmptyMVNO() {
    EXPECT_FALSE(operator_info_->tethering_allowed());
    EXPECT_TRUE(operator_info_->entitlement_config().url.empty());
    EXPECT_EQ("POST", operator_info_->entitlement_config().method);
    EXPECT_TRUE(operator_info_->entitlement_config().params.empty());
  }

  void VerifyNameListsMatch(
      const std::vector<MobileOperatorMapper::LocalizedName>&
          operator_name_list_lhs,
      const std::vector<MobileOperatorMapper::LocalizedName>&
          operator_name_list_rhs) {
    // This comparison breaks if two localized names have the same |name|.
    std::map<std::string, MobileOperatorMapper::LocalizedName> localized_names;
    for (const auto& localized_name : operator_name_list_rhs) {
      localized_names[localized_name.name] = localized_name;
    }
    for (const auto& localized_name : operator_name_list_lhs) {
      EXPECT_TRUE(localized_names.find(localized_name.name) !=
                  localized_names.end());
      EXPECT_EQ(localized_name.language,
                localized_names[localized_name.name].language);
    }
  }

  // Use this function to pre-populate all the data members of this object with
  // values matching the MNO for the database in |data_test.textproto|.
  void PopulateMNOData() {
    country_ = "us";
    requires_roaming_ = true;
    tethering_allowed_ = true;
    use_dun_apn_as_default_ = true;
    mtu_ = 1400;
    mccmnc_list_ = {"200001", "200002", "200003"};
    operator_name_list_ = {{"name200001", "en"}, {"name200002", ""}};
    apn_types_ = {"DEFAULT"};

    apn_list_.clear();
    MobileOperatorMapper::MobileAPN apn;
    apn.apn = "test@test.com";
    apn.username = "testuser";
    apn.password = "is_public_boohoohoo";
    apn.ip_type = "ipv4";
    apn.operator_name_list = {{"name200003", "hi"}};
    apn.apn_types = apn_types_;
    apn_list_.push_back(std::move(apn));

    olp_list_ = {{"some@random.com", "POST", "random_data"}};
  }

  // Use this function to pre-populate all the data members of this object with
  // values matching the MVNO for the database in |data_test.textproto|.
  void PopulateMVNOData() {
    country_ = "ca";
    requires_roaming_ = false;
    tethering_allowed_ = false;
    use_dun_apn_as_default_ = false;
    mtu_ = 1200;
    mccmnc_list_ = {"200001", "200102"};
    operator_name_list_ = {{"name200101", "en"}, {"name200102", ""}};
    apn_types_ = {"DEFAULT"};

    apn_list_.clear();
    MobileOperatorMapper::MobileAPN apn;
    apn.apn = "test2@test.com";
    apn.username = "testuser2";
    apn.password = "is_public_boohoohoo_too";
    apn.ip_type = "ipv4";
    apn.apn_types = apn_types_;
    apn.is_required_by_carrier_spec = true;
    apn_list_.push_back(std::move(apn));
    olp_list_ = {{"someother@random.com", "GET", ""}};
  }

  // Data to be verified against the database.
  std::string country_;
  bool requires_roaming_;
  bool tethering_allowed_;
  bool use_dun_apn_as_default_;
  int32_t mtu_;
  std::set<std::string> apn_types_;
  std::vector<std::string> mccmnc_list_;
  std::vector<MobileOperatorMapper::LocalizedName> operator_name_list_;
  std::vector<MobileOperatorMapper::MobileAPN> apn_list_;
  std::vector<MobileOperatorMapper::OnlinePortal> olp_list_;
};

TEST_P(MobileOperatorMapperDataTest, MNODetailedInformation) {
  // message: MNO with all the information filled in.
  // match by: MNO matches by MCCMNC
  // verify: All information is correctly loaded.
  ExpectEventCount(1);
  UpdateMCCMNC("200001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid200001");

  std::string imsi = "123456789012345";
  UpdateIMSI(imsi);
  PopulateMNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMNO(imsi);
}

TEST_P(MobileOperatorMapperDataTest, MVNOInheritsInformation) {
  // message: MVNO with name filter.
  // verify: All the missing fields are carried over to the MVNO from MNO.
  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200201");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200201");

  PopulateMNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataEmptyMVNO();
}

TEST_P(MobileOperatorMapperDataTest, MVNOOverridesInformation) {
  // match by: MNO matches by MCCMNC, MVNO by name.
  // verify: All information is correctly loaded.
  //         The MVNO in this case overrides the information provided by MNO.
  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200101");

  PopulateMVNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMVNO();
}

TEST_P(MobileOperatorMapperDataTest, NoUpdatesBeforeMNOMatch) {
  // message: MVNO.
  // - do not match MNO with mccmnc/name
  // - on different updates, verify no events.
  ExpectEventCount(0);
  UpdateMCCMNC("200999");            // No match.
  UpdateOperatorName("name200001");  // matches MNO
  UpdateOperatorName("name200101");  // matches MVNO filter.
  VerifyEventCount();
  VerifyNoMatch();
}

TEST_P(MobileOperatorMapperDataTest, UserUpdatesOverrideMVNO) {
  // - match MVNO.
  // - send updates to properties and verify events are raised and values of
  //   updated properties override the ones provided by the database.
  std::string imsi{"2009991234512345"};
  std::string iccid{"200999123456789"};
  std::string olp_url{"url@url.com"};
  std::string olp_method{"POST"};
  std::string olp_post_data{"data"};

  // Determine MVNO.
  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200101");

  // Send updates.
  ExpectEventCount(1);
  UpdateOnlinePortal(olp_url, olp_method, olp_post_data);
  UpdateIMSI(imsi);
  // No event raised because imsi is not exposed.
  UpdateICCID(iccid);
  // No event raised because ICCID is not exposed.

  VerifyEventCount();

  // Update our expectations.
  PopulateMVNOData();
  olp_list_.push_back({olp_url, olp_method, olp_post_data});

  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMVNO();
}

TEST_P(MobileOperatorMapperDataTest, RedundantUserUpdatesMVNO) {
  // - match MVNO.
  // - send redundant updates to properties.
  // - Verify no events, no updates to properties.

  // Identify MVNO.
  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200101");

  // Send redundant updates.
  // TODO(pprabhu)
  // |UpdateOnlinePortal| leads to an event because this is the first time this
  // value are set *by the user*. Although the values from the database were the
  // same, we did not use those values for filters.  It would be ideal to not
  // raise these redundant events (since no public information about the object
  // changed), but I haven't invested in doing so yet.
  ExpectEventCount(1);
  UpdateOperatorName(operator_info_->operator_name());
  UpdateOnlinePortal("someother@random.com", "GET", "");
  VerifyEventCount();
  PopulateMVNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMVNO();
}

TEST_P(MobileOperatorMapperDataTest, RedundantCachedUpdatesMVNO) {
  // message: MVNO.
  // - First send updates that don't identify MVNO, but match the data.
  // - Then idenityf an MNO and MVNO.
  // - verify that redundant information occurs only once.

  // Send redundant updates.
  ExpectEventCount(2);
  UpdateMCCMNC(operator_info_->mccmnc());
  UpdateOperatorName(operator_info_->operator_name());
  UpdateOnlinePortal("someother@random.com", "GET", "");

  // Identify MVNO.
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200101");

  PopulateMVNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMVNO();
}

TEST_P(MobileOperatorMapperDataTest, ResetClearsInformation) {
  // Repeatedly reset the object and check M[V]NO identification and data.
  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200201");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200201");
  PopulateMNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataEmptyMVNO();

  ExpectEventCount(1);
  operator_info_->Reset();
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyEventCount();
  VerifyMVNOWithUUID("uuid200101");
  PopulateMVNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMVNO();

  ExpectEventCount(1);
  operator_info_->Reset();
  VerifyEventCount();
  VerifyNoMatch();

  std::string imsi = "123456789012345";
  ExpectEventCount(1);
  UpdateIMSI(imsi);
  UpdateMCCMNC("200001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid200001");
  PopulateMNOData();
  VerifyDatabaseData();
  VerifyNonInheritableDatabaseDataMNO(imsi);
}

TEST_P(MobileOperatorMapperDataTest, FilteredOLP) {
  // We only check basic filter matching, using the fact that the regex matching
  // code is shared with the MVNO filtering, and is already well tested.
  // (1) None of the filters match.
  ExpectEventCount(1);
  UpdateMCCMNC("200001");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid200001");

  ASSERT_EQ(1, operator_info_->olp_list().size());
  // Just check that the filtered OLPs are not in the list.
  EXPECT_NE("olp@mccmnc", operator_info_->olp_list()[0].url);

  // (2) MCCMNC filter matches.
  ExpectEventCount(1);
  operator_info_->Reset();
  VerifyEventCount();
  VerifyNoMatch();

  ExpectEventCount(1);
  UpdateMCCMNC("200003");
  VerifyEventCount();
  VerifyMNOWithUUID("uuid200001");

  ASSERT_EQ(2, operator_info_->olp_list().size());
  bool found_olp_by_mccmnc = false;
  for (const auto& olp : operator_info_->olp_list()) {
    found_olp_by_mccmnc |= ("olp@mccmnc" == olp.url);
  }
  EXPECT_TRUE(found_olp_by_mccmnc);
}

class MobileOperatorMapperObserverTest : public MobileOperatorMapperMainTest {
 public:
  MobileOperatorMapperObserverTest() = default;
  MobileOperatorMapperObserverTest(const MobileOperatorMapperObserverTest&) =
      delete;
  MobileOperatorMapperObserverTest& operator=(
      const MobileOperatorMapperObserverTest&) = delete;

  // Same as |MobileOperatorMapperMainTest::SetUp|, except that we don't add a
  // default observer.
  void SetUp() override { EXPECT_TRUE(SetUpDatabase({"data_test.pbf"})); }
};

TEST_P(MobileOperatorMapperObserverTest, OnOperatorChangedCallback) {
  // - Verify the callback gets an MVNO update.
  EXPECT_CALL(on_operator_changed_cb_, Run()).Times(2);
  UpdateMCCMNC("200001");
  UpdateOperatorName("name200101");
  VerifyMVNOWithUUID("uuid200101");
  dispatcher_.DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&on_operator_changed_cb_);

  EXPECT_CALL(on_operator_changed_cb_, Run()).Times(1);
  operator_info_->Reset();
  VerifyNoMatch();
  dispatcher_.DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&on_operator_changed_cb_);
}

INSTANTIATE_TEST_SUITE_P(MobileOperatorMapperMainTestInstance,
                         MobileOperatorMapperMainTest,
                         Values(kEventCheckingPolicyStrict,
                                kEventCheckingPolicyNonStrict));
INSTANTIATE_TEST_SUITE_P(MobileOperatorMapperDataTestInstance,
                         MobileOperatorMapperDataTest,
                         Values(kEventCheckingPolicyStrict,
                                kEventCheckingPolicyNonStrict));
// It only makes sense to do strict checking here.
INSTANTIATE_TEST_SUITE_P(MobileOperatorMapperObserverTestInstance,
                         MobileOperatorMapperObserverTest,
                         Values(kEventCheckingPolicyStrict));
}  // namespace shill
