/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/probe_result_getter_impl.h"
#include "hardware_verifier/test_utils.h"

using google::protobuf::util::MessageDifferencer;

namespace hardware_verifier {

namespace {

class MockRuntimeProbeProxy : public RuntimeProbeProxy {
 public:
  MOCK_METHOD(bool,
              ProbeCategories,
              (const runtime_probe::ProbeRequest&, runtime_probe::ProbeResult*),
              (const));
  void ConfigProbeCategories(bool retval,
                             const runtime_probe::ProbeResult& resp) {
    EXPECT_CALL(*this, ProbeCategories(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(resp),
                                 testing::Return(retval)));
  }
};

}  // namespace

class TestProbeResultGetterImpl : public testing::Test {
 protected:
  void SetUp() {
    auto proxy = std::make_unique<testing::StrictMock<MockRuntimeProbeProxy>>();
    runtime_probe_proxy_ = proxy.get();
    pr_getter_.reset(new ProbeResultGetterImpl(std::move(proxy)));
  }

  testing::StrictMock<MockRuntimeProbeProxy>* runtime_probe_proxy_;
  std::unique_ptr<ProbeResultGetterImpl> pr_getter_;
};

TEST_F(TestProbeResultGetterImpl, TestGetFromRuntimeProbePass) {
  runtime_probe::ProbeResult expected_pr;
  expected_pr.add_battery()->set_name("batt_1");
  runtime_probe_proxy_->ConfigProbeCategories(true, expected_pr);

  const auto actual_pr = pr_getter_->GetFromRuntimeProbe();
  EXPECT_TRUE(actual_pr);
  EXPECT_TRUE(MessageDifferencer::Equivalent(expected_pr, actual_pr.value()));
}

TEST_F(TestProbeResultGetterImpl, TestGetFromRuntimeProbeDBusCallFail) {
  runtime_probe::ProbeResult expected_pr;
  expected_pr.add_battery()->set_name("batt_1");
  runtime_probe_proxy_->ConfigProbeCategories(false, expected_pr);

  // The method should return |false| if |runtime_probe_proxy_| returns |false|.
  EXPECT_FALSE(pr_getter_->GetFromRuntimeProbe());
}

TEST_F(TestProbeResultGetterImpl, TestGetFromRuntimeProbeProbeResultError) {
  runtime_probe::ProbeResult expected_pr;
  expected_pr.set_error(
      runtime_probe::ErrorCode::RUNTIME_PROBE_ERROR_PROBE_CONFIG_INVALID);

  runtime_probe_proxy_->ConfigProbeCategories(true, expected_pr);

  // The method should return |false| if |error| field is set in the probe
  // result.
  EXPECT_FALSE(pr_getter_->GetFromRuntimeProbe());
}

TEST_F(TestProbeResultGetterImpl, TestGetFromFile) {
  const auto tmp_path = GetTestDataPath().Append("test_root1").Append("tmp");

  runtime_probe::ProbeResult expected_pr;
  const auto actual_pr =
      pr_getter_->GetFromFile(tmp_path.Append("probe_result.prototxt"));
  EXPECT_TRUE(actual_pr);
  auto battery_values = new runtime_probe::Battery_Fields();
  battery_values->set_manufacturer("test_manufacturer_A");
  auto battery = expected_pr.add_battery();
  battery->set_allocated_values(battery_values);
  battery->set_name("batt_1");
  EXPECT_TRUE(MessageDifferencer::Equivalent(actual_pr.value(), expected_pr));

  // The |error| flag is set in the protobuf data.
  EXPECT_FALSE(pr_getter_->GetFromFile(
      tmp_path.Append("probe_result_with_error.prototxt")));

  // The given path doesn't exists.
  EXPECT_FALSE(
      pr_getter_->GetFromFile(tmp_path.Append("no_such_file.prototxt")));

  // The given file contains invalid data.
  EXPECT_FALSE(pr_getter_->GetFromFile(
      tmp_path.Append("invalid_probe_result.prototxt")));
}

}  // namespace hardware_verifier
