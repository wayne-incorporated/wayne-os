// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <set>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <re2/re2.h>

#include "shill/metrics.h"
#include "shill/mobile_operator_db/mobile_operator_db.pb.h"
#include "shill/protobuf_lite_streams.h"

using testing::Test;

namespace shill {

using MvnoMnoPair =
    std::pair<const shill::mobile_operator_db::MobileVirtualNetworkOperator*,
              const shill::mobile_operator_db::MobileNetworkOperator*>;

class ServiceProvidersTest : public testing::Test {
 protected:
  // Per-test-suite set-up.
  // Called before the first test in this test suite.
  static void SetUpTestSuite() {
    const char* out_dir = getenv("OUT");
    CHECK_NE(out_dir, nullptr);
    base::FilePath database_path =
        base::FilePath(out_dir).Append("serviceproviders.pbf");
    const char* database_path_cstr = database_path.value().c_str();
    std::unique_ptr<google::protobuf::io::CopyingInputStreamAdaptor>
        database_stream;
    database_stream.reset(protobuf_lite_file_input_stream(database_path_cstr));
    ASSERT_NE(database_stream, nullptr);
    database_ = std::make_unique<shill::mobile_operator_db::MobileOperatorDB>();
    ASSERT_TRUE(database_->ParseFromZeroCopyStream(database_stream.get()));

    // Load all MVNOs into a vector with their MNO as a secondary variable for
    // easy iteration.
    for (const auto& mno : database_->mno()) {
      for (const auto& mvno : mno.mvno()) {
        MvnoMnoPair mvno_pair(&mvno, &mno);
        mvnos_.push_back(mvno_pair);
      }
    }
    for (const auto& mvno : database_->mvno()) {
      MvnoMnoPair mvno_pair(&mvno, nullptr);
      mvnos_.push_back(mvno_pair);
    }
  }
  // Per-test-suite tear-down.
  // Called after the last test in this test suite.
  static void TearDownTestSuite() {
    database_.reset();
    database_ = nullptr;
    mvnos_.clear();
  }

  // Expensive resource shared by all tests.
  static std::unique_ptr<mobile_operator_db::MobileOperatorDB> database_;
  static std::vector<MvnoMnoPair> mvnos_;
};

std::unique_ptr<mobile_operator_db::MobileOperatorDB>
    ServiceProvidersTest::database_ = nullptr;
std::vector<MvnoMnoPair> ServiceProvidersTest::mvnos_;

TEST_F(ServiceProvidersTest, CheckUniqueUUIDs) {
  // Verify that we are not using the same uuid for different MNOs/MVNOs.
  // This is a common mistake when copy/pasting carrier info.
  std::set<std::string> uuids;
  for (const auto& mno : database_->mno()) {
    ASSERT_TRUE(mno.data().has_uuid());
    EXPECT_EQ(uuids.count(mno.data().uuid()), 0)
        << "Non unique uuid: " << mno.data().uuid();
    uuids.emplace(mno.data().uuid());
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    ASSERT_TRUE(mvno->data().has_uuid());
    EXPECT_EQ(uuids.count(mvno->data().uuid()), 0)
        << "Non unique uuid: " << mvno->data().uuid();
    uuids.emplace(mvno->data().uuid());
  }
}

TEST_F(ServiceProvidersTest, CheckMvnosWithoutFilters) {
  // If a MVNO doesn't have a filter, it will always be selected, and it will
  // override anything above its level.
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    EXPECT_TRUE(mvno->mvno_filter_size() > 0)
        << "MVNO with uuid: " << mvno->data().uuid()
        << " does not have a filter.";
  }
}

TEST_F(ServiceProvidersTest, CheckIMSIMatchesMCCMNC) {
  // Verify that the IMSI values start with one of the MCCMNC values.
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    auto mno = mvno_mno_pair.second;
    for (const auto& filter : mvno->mvno_filter()) {
      if (filter.type() == mobile_operator_db::Filter_Type_IMSI) {
        // Combine MNO and MVNO MCCMNCs
        std::set<std::string> mccmncs;
        for (const auto& mccmnc : mvno->data().mccmnc())
          mccmncs.insert(mccmnc);
        if (mno)
          for (const auto& mccmnc : mno->data().mccmnc())
            mccmncs.insert(mccmnc);

        // Validate ranges
        for (auto range : filter.range()) {
          bool found_match = false;
          for (const auto& mccmnc : mccmncs) {
            if (std::to_string(range.start()).rfind(mccmnc, 0) == 0 &&
                std::to_string(range.end()).rfind(mccmnc, 0) == 0) {
              found_match = true;
              break;
            }
          }
          EXPECT_TRUE(found_match)
              << "IMSI range " << range.start() << "-" << range.end()
              << " doesn't match any MCCMNCs in that MVNO.";
        }
        // Validate regex for simple cases:
        // - Regex that starts with 5 numeric characters.
        if (mccmncs.size() > 0 && filter.has_regex() &&
            filter.regex().size() >= 5 &&
            (filter.regex().substr(0, 5).find_first_not_of("0123456789") ==
             std::string::npos)) {
          bool found_match = false;
          for (const auto& mccmnc : mccmncs) {
            if (filter.regex().rfind(mccmnc, 0) == 0) {
              found_match = true;
              break;
            }
          }
          EXPECT_TRUE(found_match)
              << "IMSI regex " << filter.regex()
              << " doesn't match any MCCMNCs in that MVNO.";
        }
      }
    }
  }
}

TEST_F(ServiceProvidersTest, CheckIMSIRangesAreValid) {
  // Verify that different IMSI ranges don't overlap.
  // Verify that the IMSI ranges are valid(start<end).
  std::map<uint64_t, uint64_t> ranges;
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& filter : mvno->mvno_filter()) {
      if (filter.type() == mobile_operator_db::Filter_Type_IMSI) {
        for (auto range : filter.range()) {
          EXPECT_LT(range.start(), range.end());
          ASSERT_EQ(ranges.count(range.start()), 0);
          EXPECT_GT(range.start(), 0);
          EXPECT_GT(range.end(), 0);
          // Insert all ranges into |ranges| and process them later
          ranges[range.start()] = range.end();
        }
      }
    }
  }
  uint64_t previous_start = 0;
  uint64_t previous_end = 0;
  for (const auto& range : ranges) {
    if (previous_end > 0) {
      EXPECT_GT(range.first, previous_end)
          << " The IMSI ranges " << previous_start << ":" << previous_end
          << " and " << range.first << ":" << range.second << " overlap.";
    }
    previous_start = range.first;
    previous_end = range.second;
  }
}

TEST_F(ServiceProvidersTest, VerifyUniquenessOfApnHashes) {
  // This is a test related to the structured metrics(metrics.cc)
  // Verify that no 2 hashes are the same, otherwise we won't be able to know
  // which hash corresponds to which APN.
  std::map<int64_t, std::string> hashes;
  for (const auto& mno : database_->mno()) {
    for (const auto& mobile_apn : mno.data().mobile_apn()) {
      int64_t hash =
          Metrics::HashApn(mno.data().uuid(), mobile_apn.apn(),
                           mobile_apn.username(), mobile_apn.password());
      // Only check for uniqueness when not using apn_filter, as carriers
      // might use the same apn name with different localized_names when using
      // apn filters.
      if (hashes.count(hash) == 0 || !mobile_apn.apn_filter_size())
        ASSERT_EQ(hashes.count(hash), 0)
            << " Non unique hash '" << hash
            << "' for uuid:" << mno.data().uuid()
            << ", apn:" << mobile_apn.apn()
            << " username: " << mobile_apn.username()
            << ", password:" << mobile_apn.password() << ", and "
            << hashes[hash];
      hashes[hash] = mno.data().uuid() + ":" + mobile_apn.apn();
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& mobile_apn : mvno->data().mobile_apn()) {
      int64_t hash =
          Metrics::HashApn(mvno->data().uuid(), mobile_apn.apn(),
                           mobile_apn.username(), mobile_apn.password());
      ASSERT_EQ(hashes.count(hash), 0)
          << " Non unique hash '" << hash
          << "' for uuid:" << mvno->data().uuid()
          << ", apn:" << mobile_apn.apn()
          << " username: " << mobile_apn.username()
          << ", password:" << mobile_apn.password() << ", and " << hashes[hash];
      hashes[hash] = mvno->data().uuid() + ":" + mobile_apn.apn();
    }
  }
}

TEST_F(ServiceProvidersTest, CheckApnNames) {
  // According to TS 123.003 rel-15, only alphabetic characters, digits and
  // the hyphen are allowed.

  re2::RE2 chars_regex = {"[^a-zA-Z\\d\\-\\.]"};
  re2::RE2 begin_end_regex = {"^[a-zA-Z\\d].*[a-zA-Z\\d]$"};
  auto regex_check = [&chars_regex, &begin_end_regex](auto uuid, auto apn) {
    EXPECT_FALSE(RE2::PartialMatch(apn, chars_regex))
        << "MVNO with uuid: " << uuid << ", apn:'" << apn << "'"
        << " contains characters that are non alphanumeric or hyphen.";
    EXPECT_TRUE(RE2::FullMatch(apn, begin_end_regex))
        << "MVNO with uuid: " << uuid << ", apn:'" << apn << "'"
        << " has a non alphanumeric char in the first or last position.";
  };
  for (const auto& mno : database_->mno()) {
    for (const auto& mobile_apn : mno.data().mobile_apn()) {
      regex_check(mno.data().uuid(), mobile_apn.apn());
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& mobile_apn : mvno->data().mobile_apn()) {
      regex_check(mvno->data().uuid(), mobile_apn.apn());
    }
  }
}

TEST_F(ServiceProvidersTest, CheckApnTypes) {
  // Verify that all apns have an ApnType.

  for (const auto& mno : database_->mno()) {
    for (const auto& mobile_apn : mno.data().mobile_apn()) {
      ASSERT_TRUE(mobile_apn.type().size() > 0)
          << " MVNO with uuid: " << mno.data().uuid() << ", apn:'"
          << mobile_apn.apn() << "' has no ApnType.";
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& mobile_apn : mvno->data().mobile_apn()) {
      ASSERT_TRUE(mobile_apn.type().size() > 0)
          << " MVNO with uuid: " << mvno->data().uuid() << ", apn:'"
          << mobile_apn.apn() << "' has no ApnType.";
    }
  }
}

TEST_F(ServiceProvidersTest, CheckConflictingFilters) {
  // Verify that some filter configurations don't exist.
  // regex && exclude_regex is OK
  // range && (regex || exclude_regex) is NOK

  auto filter_check = [](auto filter, auto filter_name, auto uuid) {
    ASSERT_TRUE(filter.has_regex() || filter.has_exclude_regex() ||
                (filter.range_size() > 0))
        << "MVNO/MNO with uuid: " << uuid
        << "contains an empty filter of type '" << filter_name << "'";
    ASSERT_FALSE((filter.range_size() > 0) &&
                 (filter.has_regex() || filter.has_exclude_regex()))
        << "MVNO/MNO with uuid: " << uuid
        << "contains a conflicting filter of type '" << filter_name << "'";
  };
  // MobileVirtualNetworkOperator->mvno_filter
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& filter : mvno->mvno_filter()) {
      filter_check(filter, mvno->data().uuid(), "mvno_filter");
    }
  }

  // Data->olp->olp_filter
  for (const auto& mno : database_->mno()) {
    for (const auto& olp : mno.data().olp()) {
      if (olp.has_olp_filter()) {
        filter_check(olp.olp_filter(), mno.data().uuid(), "olp_filter");
      }
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& olp : mvno->data().olp()) {
      if (olp.has_olp_filter()) {
        filter_check(olp.olp_filter(), mvno->data().uuid(), "olp_filter");
      }
    }
  }

  // Data->roaming_filter
  for (const auto& mno : database_->mno()) {
    for (const auto& filter : mno.data().roaming_filter()) {
      filter_check(filter, mno.data().uuid(), "olp_filter");
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& filter : mvno->data().roaming_filter()) {
      filter_check(filter, mvno->data().uuid(), "olp_filter");
    }
  }

  // MobileAPN->apn_filter
  for (const auto& mno : database_->mno()) {
    for (const auto& mobile_apn : mno.data().mobile_apn()) {
      for (const auto& filter : mobile_apn.apn_filter()) {
        filter_check(filter, mno.data().uuid(), "apn_filter");
      }
    }
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& mobile_apn : mvno->data().mobile_apn()) {
      for (const auto& filter : mobile_apn.apn_filter()) {
        filter_check(filter, mvno->data().uuid(), "apn_filter");
      }
    }
  }
}

TEST_F(ServiceProvidersTest, CheckForUnusedApns) {
  // When an APN has is_required_by_carrier_spec set to true, no other APNs of
  // that type will be used. The flag is intended to block APNs from the UI, so
  // check that no APNS in modb are blocked.
  auto check_for_unused_apns =
      [](const std::string& mno_mvno,
         const ::shill::mobile_operator_db::Data& data) {
        std::map<int, const shill::mobile_operator_db::MobileAPN*> apn_per_type;
        for (int i = 0; i < data.mobile_apn_size(); i++) {
          auto mobile_apn = &data.mobile_apn()[i];
          for (auto apn_type : mobile_apn->type()) {
            if (apn_per_type.find(apn_type) == apn_per_type.end()) {
              apn_per_type[apn_type] = mobile_apn;
            } else {
              ASSERT_EQ(apn_per_type[apn_type]->is_required_by_carrier_spec(),
                        mobile_apn->is_required_by_carrier_spec())
                  << " " << mno_mvno << " with uuid: " << data.uuid()
                  << ", apn:'" << mobile_apn->apn()
                  << "' is overriding apn:" << apn_per_type[apn_type]->apn();
            }
          }
        }
      };

  for (const auto& mno : database_->mno()) {
    check_for_unused_apns("MNO", mno.data());
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    check_for_unused_apns("MVNO", mvno->data());
  }
}

}  // namespace shill
