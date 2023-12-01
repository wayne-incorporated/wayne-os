/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_VERIFIER_IMPL_H_
#define HARDWARE_VERIFIER_VERIFIER_IMPL_H_

#include "hardware_verifier/verifier.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <chromeos-config/libcros_config/cros_config.h>
#include <google/protobuf/descriptor.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace hardware_verifier {

constexpr auto kCrosConfigModelNamePath = "/";
constexpr auto kCrosConfigModelNameKey = "name";

class VerifierImpl : public Verifier {
 public:
  VerifierImpl();

  std::optional<HwVerificationReport> Verify(
      const runtime_probe::ProbeResult& probe_result,
      const HwVerificationSpec& hw_verification_spec) const override;

  void SetCrosConfigForTesting(
      std::unique_ptr<brillo::CrosConfigInterface> cros_config);

 private:
  struct CompCategoryInfo {
    // Enum value of of this category.
    runtime_probe::ProbeRequest_SupportCategory enum_value;

    // Enum name of this category.
    std::string enum_name;

    // The field descriptor of the component list in
    // |runtime_probe::ProbeResult|.
    const google::protobuf::FieldDescriptor* probe_result_comp_field;

    // The field descriptor of the component name in
    // |runtime_probe::ProbeResult|.
    const google::protobuf::FieldDescriptor* probe_result_comp_name_field;

    // The field descriptor of the component values in
    // |runtime_probe::ProbeResult|.
    const google::protobuf::FieldDescriptor* probe_result_comp_values_field;

    // The field descriptor of the component values in |HwVerificationReport|.
    const google::protobuf::FieldDescriptor* report_comp_values_field;
  };

  std::unique_ptr<brillo::CrosConfigInterface> cros_config_;

  // An array that records each component category's related info like enum
  // value and name.
  std::vector<CompCategoryInfo> comp_category_infos_;

  std::string GetModelName() const;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_VERIFIER_IMPL_H_
