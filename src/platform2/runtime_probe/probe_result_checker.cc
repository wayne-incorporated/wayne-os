// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/probe_result_checker.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/values.h>

#include "runtime_probe/field_converter.h"

namespace runtime_probe {

namespace {
using ReturnCode = FieldConverter::ReturnCode;
}  // namespace

std::unique_ptr<ProbeResultChecker> ProbeResultChecker::FromValue(
    const base::Value& value) {
  if (value.is_dict())
    return ProbeResultCheckerDict::FromValue(value);
  if (value.is_list())
    return ProbeResultCheckerList::FromValue(value);
  LOG(ERROR) << "invalid type for 'expect' field: "
             << base::Value::GetTypeName(value.type());
  return nullptr;
}

std::unique_ptr<ProbeResultCheckerDict> ProbeResultCheckerDict::FromValue(
    const base::Value& dict_value) {
  auto instance = std::make_unique<ProbeResultCheckerDict>();
  for (const auto& entry : dict_value.GetDict()) {
    const auto& key = entry.first;
    const auto& val = entry.second;
    auto print_error_and_return = [&val]() {
      LOG(ERROR) << "'expect' attribute should be a list whose values are"
                 << "[<required:bool>, <expected_type:string>, "
                 << "<optional_validate_rule:string>], got: " << val;
      return nullptr;
    };

    const auto& list_value = val.GetList();

    if (list_value.size() < 2 || list_value.size() > 3)
      return print_error_and_return();

    if (!list_value[0].is_bool())
      return print_error_and_return();
    bool required = list_value[0].GetBool();
    auto* target =
        required ? &instance->required_fields_ : &instance->optional_fields_;

    if (!list_value[1].is_string())
      return print_error_and_return();
    const auto& expect_type = list_value[1].GetString();

    std::string validate_rule;
    if (list_value.size() == 3) {
      if (!list_value[2].is_string())
        return print_error_and_return();
      validate_rule = list_value[2].GetString();
    }

    std::unique_ptr<FieldConverter> converter = nullptr;
    if (expect_type == "str") {
      converter = StringFieldConverter::Build(validate_rule);
    } else if (expect_type == "int") {
      converter = IntegerFieldConverter::Build(validate_rule);
    } else if (expect_type == "double") {
      converter = DoubleFieldConverter::Build(validate_rule);
    } else if (expect_type == "hex") {
      converter = HexFieldConverter::Build(validate_rule);
    }

    if (converter == nullptr) {
      LOG(ERROR) << "Cannot build converter, 'expect_type': " << expect_type
                 << ", 'validate_rule': " << validate_rule;
      return nullptr;
    } else {
      (*target)[key] = std::move(converter);
    }
  }

  return instance;
}

bool ProbeResultCheckerDict::Apply(base::Value* probe_result) const {
  bool success = true;

  CHECK(probe_result != nullptr);
  const auto& probe_result_dict = probe_result->GetDict();

  // Try to convert and validate each required fields.
  // Any failures will cause the final result be |false|.
  for (const auto& entry : required_fields_) {
    const auto& key = entry.first;
    const auto& converter = entry.second;
    if (!probe_result_dict.Find(key)) {
      DVLOG(2) << "Missing key: " << key;
      success = false;
      break;
    }

    auto return_code = converter->Convert(key, probe_result);
    if (return_code != ReturnCode::OK) {
      auto* value = probe_result_dict.Find(key);
      LOG(ERROR) << "Failed to apply " << converter->ToString() << " on "
                 << *value << "(ReturnCode = " << static_cast<int>(return_code)
                 << ")";

      success = false;
      break;
    }
  }

  // |ProbeStatement| will remove this element from final results, there is no
  // need to continue.
  if (!success) {
    VLOG(3) << "probe_result = " << *probe_result;
    return false;
  }

  // Try to convert and validate each optional fields.
  // For failures, just remove them from probe_result and continue.
  for (const auto& entry : optional_fields_) {
    const auto& key = entry.first;
    const auto& converter = entry.second;
    if (!probe_result_dict.Find(key))
      continue;

    auto return_code = converter->Convert(key, probe_result);
    if (return_code != ReturnCode::OK) {
      VLOG(1) << "Optional field '" << key << "' has unexpected value, "
              << "remove it from probe result.";
      probe_result->GetDict().Remove(key);
    }
  }

  // Now all fields should have the correct type, let's validate them.
  for (const auto& entry : required_fields_) {
    auto return_code = entry.second->Validate(entry.first, probe_result);
    if (return_code != ReturnCode::OK) {
      success = false;
      break;
    }
  }
  // Optional fields shouldn't have expect value.

  return success;
}

std::unique_ptr<ProbeResultCheckerList> ProbeResultCheckerList::FromValue(
    const base::Value& list_value) {
  auto instance = std::make_unique<ProbeResultCheckerList>();
  for (auto& dv : list_value.GetList()) {
    if (!dv.is_dict()) {
      LOG(ERROR) << "checker should be a valid dictionary";
      return nullptr;
    }
    auto checker = ProbeResultCheckerDict::FromValue(dv);
    if (!checker)
      return nullptr;
    instance->checkers.push_back(std::move(checker));
  }
  return instance;
}

bool ProbeResultCheckerList::Apply(base::Value* probe_result) const {
  CHECK(probe_result != nullptr);

  if (checkers.size() == 0)
    return true;
  for (const auto& checker : checkers) {
    // Pass the copy of |probe_result| in as the checker may modify it.
    auto probe_result_copy = probe_result->Clone();
    if (checker->Apply(&probe_result_copy)) {
      // We need the values in |probe_result| to be converted, so update
      // |probe_result| if it passes the validation.
      *probe_result = std::move(probe_result_copy);
      return true;
    }
  }
  return false;
}

}  // namespace runtime_probe
