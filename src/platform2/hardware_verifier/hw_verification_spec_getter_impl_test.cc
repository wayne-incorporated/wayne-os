/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <string>

#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_spec_getter_impl.h"
#include "hardware_verifier/test_utils.h"

using google::protobuf::util::MessageDifferencer;

namespace hardware_verifier {

namespace {

class MockVbSystemPropertyGetter : public VbSystemPropertyGetter {
 public:
  MOCK_CONST_METHOD0(GetCrosDebug, int());
};

}  // namespace

class HwVerificationSpecGetterImplTest : public testing::Test {
 protected:
  void SetUp() {
    mock_vb_system_property_getter_ = new MockVbSystemPropertyGetter();
    vp_getter_ = std::make_unique<HwVerificationSpecGetterImpl>(
        std::unique_ptr<VbSystemPropertyGetter>(
            mock_vb_system_property_getter_));
    vp_getter_->root_ = GetTestDataPath();

    auto comp_info = golden_expected_vp_.add_component_infos();
    comp_info->set_component_category(
        runtime_probe::ProbeRequest_SupportCategory_battery);
    comp_info->set_component_uuid("batt1");
    comp_info->set_qualification_status(QualificationStatus::QUALIFIED);
    comp_info = golden_expected_vp_.add_component_infos();
    comp_info->set_component_category(
        runtime_probe::ProbeRequest_SupportCategory_storage);
    comp_info->set_component_uuid("storage1");
    comp_info->set_qualification_status(QualificationStatus::REJECTED);
    comp_info = golden_expected_vp_.add_component_infos();
    comp_info->set_component_category(
        runtime_probe::ProbeRequest_SupportCategory_storage);
    comp_info->set_component_uuid("storage2");
    comp_info->set_qualification_status(QualificationStatus::UNQUALIFIED);
  }

  void SetFakeRoot(const std::string& root_name) {
    vp_getter_->root_ = GetTestDataPath().Append(root_name);
  }

  void SetCrosDebugFlag(int value) {
    EXPECT_CALL(*mock_vb_system_property_getter_, GetCrosDebug())
        .WillRepeatedly(testing::Return(value));
  }

  MockVbSystemPropertyGetter* mock_vb_system_property_getter_;
  std::unique_ptr<HwVerificationSpecGetterImpl> vp_getter_;
  HwVerificationSpec golden_expected_vp_;
};

TEST_F(HwVerificationSpecGetterImplTest, TestGetDefaultPass) {
  SetFakeRoot("test_root1");
  const auto actual_vp = vp_getter_->GetDefault();
  EXPECT_TRUE(actual_vp);
  EXPECT_TRUE(
      MessageDifferencer::Equivalent(actual_vp.value(), golden_expected_vp_));
}

TEST_F(HwVerificationSpecGetterImplTest, TestGetDefaultFail) {
  // The verification spec file in |test_root2| contains invalid data.
  SetFakeRoot("test_root2");
  EXPECT_FALSE(vp_getter_->GetDefault());
}

TEST_F(HwVerificationSpecGetterImplTest, TestGetFromFileCrosDebugOff) {
  const auto tmp_path = GetTestDataPath().Append("test_root1").Append("tmp");

  SetCrosDebugFlag(0);
  EXPECT_FALSE(vp_getter_->GetFromFile(
      tmp_path.Append("hw_verification_spec1.prototxt")));
}

TEST_F(HwVerificationSpecGetterImplTest, TestGetFromFileNoCheckCrosDebug) {
  SetCrosDebugFlag(1);

  const auto tmp_path = GetTestDataPath().Append("test_root1").Append("tmp");

  const auto actual_vp = vp_getter_->GetFromFile(
      tmp_path.Append("hw_verification_spec1.prototxt"));
  EXPECT_TRUE(actual_vp);
  EXPECT_TRUE(
      MessageDifferencer::Equivalent(actual_vp.value(), golden_expected_vp_));

  // |hw_verification_spec2.prototxt| contains invalid data.
  EXPECT_FALSE(vp_getter_->GetFromFile(
      tmp_path.Append("hw_verification_spec2.prototxt")));

  // |hw_verification_spec3.prototxt| doesn't exist.
  EXPECT_FALSE(vp_getter_->GetFromFile(
      tmp_path.Append("hw_verification_spec3.prototxt")));
}

}  // namespace hardware_verifier
