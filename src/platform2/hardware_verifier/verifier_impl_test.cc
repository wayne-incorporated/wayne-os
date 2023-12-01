/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/hw_verification_spec_getter_impl.h"
#include "hardware_verifier/probe_result_getter_impl.h"
#include "hardware_verifier/test_utils.h"
#include "hardware_verifier/verifier_impl.h"

using google::protobuf::util::MessageDifferencer;

namespace hardware_verifier {

namespace {

constexpr auto kPrototxtExtension = ".prototxt";

class FakeVbSystemPropertyGetter : public VbSystemPropertyGetter {
 public:
  int GetCrosDebug() const override { return 1; }
};

}  // namespace

class TestVerifierImpl : public testing::Test {
 protected:
  void SetUp() override {
    pr_getter_.reset(new ProbeResultGetterImpl());
    vs_getter_.reset(new HwVerificationSpecGetterImpl(
        std::unique_ptr<VbSystemPropertyGetter>(
            new FakeVbSystemPropertyGetter())));

    hw_verification_report_differencer_.TreatAsSet(
        HwVerificationReport::descriptor()->FindFieldByName(
            "found_component_infos"));
    const auto* category_enum_desc =
        runtime_probe::ProbeRequest_SupportCategory_descriptor();
    for (int i = 0; i < category_enum_desc->value_count(); ++i) {
      const auto* category_enum_value_desc = category_enum_desc->value(i);
      if (category_enum_value_desc->number() ==
          runtime_probe::ProbeRequest_SupportCategory_UNKNOWN)
        continue;
      const auto* field_desc =
          HwVerificationReport_GenericDeviceInfo::descriptor()->FindFieldByName(
              category_enum_value_desc->name());
      if (field_desc) {
        hw_verification_report_differencer_.TreatAsSet(field_desc);
      }
    }
  }

  HwVerificationSpec LoadHwVerificationSpec(const base::FilePath& file_path) {
    const auto& result = vs_getter_->GetFromFile(file_path);
    EXPECT_TRUE(result);
    return result.value();
  }

  runtime_probe::ProbeResult LoadProbeResult(const base::FilePath& file_path) {
    const auto& result = pr_getter_->GetFromFile(file_path);
    EXPECT_TRUE(result);
    return result.value();
  }

  // Sets model names to the given value.
  void SetModelName(const std::string& val) {
    if (cros_config_) {
      cros_config_->SetString(kCrosConfigModelNamePath, kCrosConfigModelNameKey,
                              val);
    }
  }

  void TestVerifySuccWithSampleData(const std::string& probe_result_sample_name,
                                    const std::string& spec_sample_name,
                                    const std::string& report_sample_name) {
    const auto& probe_result = LoadProbeResult(GetSampleDataPath().Append(
        probe_result_sample_name + kPrototxtExtension));
    const auto& hw_verification_spec = LoadHwVerificationSpec(
        GetSampleDataPath().Append(spec_sample_name + kPrototxtExtension));
    const auto& expect_hw_verification_report = LoadHwVerificationReport(
        GetSampleDataPath().Append(report_sample_name + kPrototxtExtension));

    VerifierImpl verifier;
    auto cros_config = std::make_unique<brillo::FakeCrosConfig>();
    cros_config_ = cros_config.get();
    verifier.SetCrosConfigForTesting(std::move(cros_config));
    SetModelName("");
    const auto& actual_hw_verification_report =
        verifier.Verify(probe_result, hw_verification_spec);
    EXPECT_TRUE(actual_hw_verification_report);
    EXPECT_TRUE(hw_verification_report_differencer_.Compare(
        actual_hw_verification_report.value(), expect_hw_verification_report));
  }

  void TestVerifyFailWithSampleData(const std::string& probe_result_sample_name,
                                    const std::string& spec_sample_name) {
    const auto& probe_result = LoadProbeResult(GetSampleDataPath().Append(
        probe_result_sample_name + kPrototxtExtension));
    const auto& hw_verification_spec = LoadHwVerificationSpec(
        GetSampleDataPath().Append(spec_sample_name + kPrototxtExtension));

    VerifierImpl verifier;
    auto cros_config = std::make_unique<brillo::FakeCrosConfig>();
    cros_config_ = cros_config.get();
    verifier.SetCrosConfigForTesting(std::move(cros_config));
    SetModelName("");
    EXPECT_FALSE(verifier.Verify(probe_result, hw_verification_spec));
  }

  base::FilePath GetSampleDataPath() {
    return GetTestDataPath().Append("verifier_impl_sample_data");
  }

 private:
  brillo::FakeCrosConfig* cros_config_;
  std::unique_ptr<ProbeResultGetter> pr_getter_;
  std::unique_ptr<HwVerificationSpecGetter> vs_getter_;
  MessageDifferencer hw_verification_report_differencer_;
};

TEST_F(TestVerifierImpl, TestVerifySuccWithSample1) {
  TestVerifySuccWithSampleData("probe_result_1", "hw_verification_spec_1",
                               "expect_hw_verification_report_1");
}

TEST_F(TestVerifierImpl, TestVerifySuccWithSample2) {
  TestVerifySuccWithSampleData("probe_result_2", "hw_verification_spec_1",
                               "expect_hw_verification_report_2");
}

TEST_F(TestVerifierImpl, TestVerifySuccWithSample3) {
  TestVerifySuccWithSampleData("probe_result_3", "hw_verification_spec_1",
                               "expect_hw_verification_report_3");
}

TEST_F(TestVerifierImpl, TestVerifySuccWithSample4) {
  TestVerifySuccWithSampleData("probe_result_4", "hw_verification_spec_1",
                               "expect_hw_verification_report_4");
}

TEST_F(TestVerifierImpl, TestVerifyFailWithSample1) {
  TestVerifyFailWithSampleData("probe_result_bad_1", "hw_verification_spec_1");
}

TEST_F(TestVerifierImpl, TestVerifyFailWithSample2) {
  TestVerifyFailWithSampleData("probe_result_bad_2", "hw_verification_spec_1");
}

TEST_F(TestVerifierImpl, TestVerifyFailWithSample3) {
  TestVerifyFailWithSampleData("probe_result_1", "hw_verification_spec_bad_1");
}

TEST_F(TestVerifierImpl, TestVerifyFailWithSample4) {
  TestVerifyFailWithSampleData("probe_result_1", "hw_verification_spec_bad_2");
}

}  // namespace hardware_verifier
