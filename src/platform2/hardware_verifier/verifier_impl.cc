/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/verifier_impl.h"

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace hardware_verifier {

namespace {

using CppType = google::protobuf::FieldDescriptor::CppType;
using SupportCategory = runtime_probe::ProbeRequest_SupportCategory;

constexpr int kCppTypeMsg = CppType::CPPTYPE_MESSAGE;
constexpr int kCppTypeStr = CppType::CPPTYPE_STRING;

constexpr auto kGenericComponentName = "generic";
constexpr auto kNoMatchComponentName = "NO_MATCH";

void FilterComponentFields(google::protobuf::Message* comp_values,
                           const std::set<std::string>& comp_value_allowlist) {
  const auto* comp_values_refl = comp_values->GetReflection();
  const auto* comp_values_desc = comp_values->GetDescriptor();
  for (int j = 0; j < comp_values_desc->field_count(); ++j) {
    const auto* field = comp_values_desc->field(j);
    if (!comp_value_allowlist.count(field->name())) {
      comp_values_refl->ClearField(comp_values, field);
    }
  }
}

void SetComponentFields(ComponentInfo* component_info,
                        SupportCategory category,
                        const google::protobuf::Message& values) {
  auto comp_fields = component_info->mutable_component_fields();
  auto comp_fields_desc = comp_fields->GetDescriptor();
  auto comp_fields_refl = comp_fields->GetReflection();
  auto category_name =
      runtime_probe::ProbeRequest_SupportCategory_Name(category);
  auto* fields_desc = comp_fields_desc->FindFieldByName(category_name);
  DCHECK(fields_desc && fields_desc->cpp_type() == kCppTypeMsg &&
         fields_desc->is_optional());
  auto* fields = comp_fields_refl->MutableMessage(comp_fields, fields_desc);
  fields->CopyFrom(values);
}

void AddFoundComponentInfo(HwVerificationReport* hw_verification_report,
                           SupportCategory component_category,
                           const std::string& comp_name,
                           google::protobuf::Message* comp_values,
                           QualificationStatus status) {
  auto* found_comp_info = hw_verification_report->add_found_component_infos();
  found_comp_info->set_component_category(component_category);
  found_comp_info->set_component_uuid(comp_name);
  found_comp_info->set_qualification_status(status);
  if (comp_values) {
    SetComponentFields(found_comp_info, component_category, *comp_values);
  }
  if (status != QualificationStatus::QUALIFIED) {
    hw_verification_report->set_is_compliant(false);
  }
}

bool IsModelComponent(const ComponentInfo& comp_info,
                      const std::string& model_name) {
  if (model_name.empty())
    return true;

  const auto& parts = base::SplitString(model_name, "_", base::KEEP_WHITESPACE,
                                        base::SPLIT_WANT_ALL);
  return base::StartsWith(comp_info.component_uuid(), parts[0] + "_");
}

}  // namespace

VerifierImpl::VerifierImpl() {
  cros_config_ = std::make_unique<brillo::CrosConfig>();
  // Resolve |comp_category_infos_| in the constructor.
  const auto* category_enum_desc =
      runtime_probe::ProbeRequest_SupportCategory_descriptor();
  comp_category_infos_.resize(category_enum_desc->value_count());

  const auto* probe_result_desc = runtime_probe::ProbeResult::descriptor();
  const auto* generic_device_info_desc =
      HwVerificationReport_GenericDeviceInfo::descriptor();
  for (int i = 0; i < category_enum_desc->value_count(); ++i) {
    auto* comp_category_info = &comp_category_infos_[i];
    const auto& comp_category_name = category_enum_desc->value(i)->name();

    comp_category_info->enum_value =
        static_cast<SupportCategory>(category_enum_desc->value(i)->number());
    comp_category_info->enum_name = comp_category_name;

    if (comp_category_info->enum_value ==
        runtime_probe::ProbeRequest_SupportCategory_UNKNOWN)
      continue;

    const auto* field_desc =
        probe_result_desc->FindFieldByName(comp_category_name);
    DCHECK(field_desc && field_desc->cpp_type() == kCppTypeMsg &&
           field_desc->is_repeated())
        << "Field (" << comp_category_name << ") must be a repeated field for "
        << "the HW components in |runtime_probe::ProbeResult|.";
    comp_category_info->probe_result_comp_field = field_desc;

    const auto* probe_result_comp_desc = field_desc->message_type();
    field_desc = probe_result_comp_desc->FindFieldByName("name");
    DCHECK(field_desc && field_desc->cpp_type() == kCppTypeStr &&
           field_desc->is_optional())
        << "Field (" << comp_category_name
        << ") should contain a string of the name of the component.";
    comp_category_info->probe_result_comp_name_field = field_desc;

    field_desc = probe_result_comp_desc->FindFieldByName("values");
    DCHECK(field_desc && field_desc->cpp_type() == kCppTypeMsg &&
           field_desc->is_optional())
        << "Field (" << comp_category_name
        << ") should contain a message field for the component values.";
    comp_category_info->probe_result_comp_values_field = field_desc;

    field_desc = generic_device_info_desc->FindFieldByName(comp_category_name);
    if (field_desc) {
      DCHECK(field_desc->cpp_type() == kCppTypeMsg && field_desc->is_repeated())
          << "|hardware_verifier::HwVerificationReport_GenericDeviceInfo| "
          << "should contain a repeated field for the generic ("
          << comp_category_name << ") components.";
    } else {
      VLOG(1) << "(" << comp_category_name << ") field is not found in "
              << "|hardware_verifier::HwVerificationReport_GenericDeviceInfo|, "
              << "will ignore the generic component of that category.";
    }
    comp_category_info->report_comp_values_field = field_desc;
  }
}

std::optional<HwVerificationReport> VerifierImpl::Verify(
    const runtime_probe::ProbeResult& probe_result,
    const HwVerificationSpec& hw_verification_spec) const {
  // A dictionary of 'expected_component_category => seen'.
  std::map<SupportCategory, bool> seen_comp;
  // Collect the categories of generic components we found.
  std::set<SupportCategory> seen_generic_comp;

  // A dictionary which maps (component_category, component_uuid) to its
  // qualification status.
  std::map<SupportCategory, std::map<std::string, QualificationStatus>>
      qual_status_dict;
  const auto model_name = GetModelName();
  for (const auto& comp_info : hw_verification_spec.component_infos()) {
    if (!IsModelComponent(comp_info, model_name))
      continue;
    const auto& category = comp_info.component_category();
    const auto& uuid = comp_info.component_uuid();
    const auto& qualification_status = comp_info.qualification_status();
    const auto& insert_result =
        qual_status_dict[category].emplace(uuid, qualification_status);
    if (!insert_result.second) {
      LOG(ERROR)
          << "The verification spec contains duplicated component infos.";
      return std::nullopt;
    }

    // We expect to see this component in probe result.
    seen_comp[category] = false;
  }

  // A dictionary which maps component_category to the field names in the
  // allowlist.
  std::map<SupportCategory, std::set<std::string>>
      generic_comp_value_allowlists;
  for (const auto& spec_info :
       hw_verification_spec.generic_component_value_allowlists()) {
    const auto& insert_result = generic_comp_value_allowlists.emplace(
        spec_info.component_category(),
        std::set<std::string>(spec_info.field_names().cbegin(),
                              spec_info.field_names().cend()));
    if (!insert_result.second) {
      LOG(ERROR) << "Duplicated allowlist tables for category (num="
                 << spec_info.component_category() << ") are detected in the "
                 << "verification spec.";
      return std::nullopt;
    }
  }

  HwVerificationReport hw_verification_report;
  hw_verification_report.set_is_compliant(true);
  auto* generic_device_info =
      hw_verification_report.mutable_generic_device_info();
  const auto* generic_device_info_refl = generic_device_info->GetReflection();

  const auto* probe_result_refl = probe_result.GetReflection();
  for (const auto& comp_category_info : comp_category_infos_) {
    if (comp_category_info.enum_value ==
        runtime_probe::ProbeRequest_SupportCategory_UNKNOWN)
      continue;
    const auto& comp_name_to_qual_status =
        qual_status_dict[comp_category_info.enum_value];

    // the default allowlist is empty.
    const auto& generic_comp_value_allowlist =
        generic_comp_value_allowlists[comp_category_info.enum_value];

    const auto& num_comps = probe_result_refl->FieldSize(
        probe_result, comp_category_info.probe_result_comp_field);
    for (int i = 0; i < num_comps; ++i) {
      const auto& comp = probe_result_refl->GetRepeatedMessage(
          probe_result, comp_category_info.probe_result_comp_field, i);
      const auto* comp_refl = comp.GetReflection();
      const auto& comp_name = comp_refl->GetString(
          comp, comp_category_info.probe_result_comp_name_field);
      const auto& comp_values = comp_refl->GetMessage(
          comp, comp_category_info.probe_result_comp_values_field);

      // If the component name is "generic", add it to |generic_device_info|
      // in the report.
      if (comp_name == kGenericComponentName) {
        seen_generic_comp.insert(comp_category_info.enum_value);
        if (!comp_category_info.report_comp_values_field) {
          VLOG(1) << "Ignore the generic component of ("
                  << comp_category_info.enum_name << ") category.";
        } else {
          // Duplicate the original values and filter the fields by the
          // allowlist.
          auto* generic_comp_values = generic_device_info_refl->AddMessage(
              generic_device_info, comp_category_info.report_comp_values_field);
          generic_comp_values->CopyFrom(comp_values);
          FilterComponentFields(generic_comp_values,
                                generic_comp_value_allowlist);
        }
        continue;
      }

      // If the component name is not "generic", do the regular qualification
      // status check.
      const auto& qual_status_it = comp_name_to_qual_status.find(comp_name);
      if (qual_status_it == comp_name_to_qual_status.end()) {
        LOG(ERROR) << "The probe result contains unregonizable components "
                   << "(category=" << comp_category_info.enum_name
                   << ", uuid=" << comp_name << ").";
        return std::nullopt;
      }
      // TODO(b147654337): How about components that are "missing", that is:
      //   - It is expected on the system (according to SKU or MODEL).
      //   - We cannot find this in generic nor non-generic components.
      auto* filtered_comp_values = comp_values.New();
      filtered_comp_values->CopyFrom(comp_values);
      FilterComponentFields(filtered_comp_values, generic_comp_value_allowlist);
      AddFoundComponentInfo(&hw_verification_report,
                            comp_category_info.enum_value, comp_name,
                            filtered_comp_values, qual_status_it->second);
      seen_comp[comp_category_info.enum_value] = true;
      delete filtered_comp_values;
    }
  }

  for (const auto& it : seen_comp) {
    // We have found a generic component in this category, but this doesn't have
    // any qualification status.
    if (!it.second && seen_generic_comp.count(it.first)) {
      AddFoundComponentInfo(&hw_verification_report, it.first,
                            kNoMatchComponentName, nullptr,
                            QualificationStatus::NO_MATCH);
    }
  }

  // TODO(yhong): Implement the SKU specific checks.
  return hw_verification_report;
}

void VerifierImpl::SetCrosConfigForTesting(
    std::unique_ptr<brillo::CrosConfigInterface> cros_config) {
  cros_config_ = std::move(cros_config);
}

std::string VerifierImpl::GetModelName() const {
  std::string model_name;

  if (cros_config_ &&
      cros_config_->GetString(kCrosConfigModelNamePath, kCrosConfigModelNameKey,
                              &model_name))
    return model_name;

  // Fallback to sys_info.
  return base::SysInfo::GetLsbReleaseBoard();
}

}  // namespace hardware_verifier
