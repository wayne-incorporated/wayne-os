// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/probe_function.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/logging.h>

#include "runtime_probe/functions/all_functions.h"
#include "runtime_probe/system/context.h"

namespace runtime_probe {

using DataType = typename ProbeFunction::DataType;

auto ProbeFunction::registered_functions_ =
    AllFunctions::ConstructRegisteredFunctionTable();

ProbeFunction::ProbeFunction() = default;

ProbeFunction::~ProbeFunction() = default;

std::unique_ptr<ProbeFunction> ProbeFunction::FromValue(const base::Value& dv) {
  if (!dv.is_dict()) {
    LOG(ERROR) << "ProbeFunction::FromValue takes a dictionary as parameter";
    return nullptr;
  }
  const auto& dict = dv.GetDict();

  auto size = dict.size();
  if (size == 0) {
    LOG(ERROR) << "No function name found in the ProbeFunction dictionary";
    return nullptr;
  }

  if (size > 1) {
    LOG(ERROR) << "More than 1 function names specified in the ProbeFunction"
                  " dictionary";
    return nullptr;
  }

  const auto& it = dict.begin();

  // function_name is the only key exists in the dictionary */
  const auto& function_name = it->first;
  const auto& kwargs = it->second;

  if (registered_functions_.find(function_name) ==
      registered_functions_.end()) {
    // TODO(stimim): Should report an error.
    LOG(ERROR) << "Function \"" << function_name << "\" not found";
    return nullptr;
  }

  if (!kwargs.is_dict()) {
    LOG(ERROR) << "Function argument should be a dictionary";
    return nullptr;
  }

  return static_cast<std::unique_ptr<ProbeFunction>>(
      registered_functions_[function_name](kwargs.GetDict()));
}

int ProbeFunction::EvalInHelper(std::string* /*output*/) const {
  LOG(ERROR) << "Probe function \"" << GetFunctionName()
             << "\" cannot be invoked in helper.";
  return -1;
}

void ProbeFunction::RegisterArgumentParser(const std::string field_name,
                                           ArgumentParser* parser) {
  CHECK(!argument_parsers_.count(field_name))
      << "Register duplicated argument " << field_name;
  argument_parsers_[field_name] = parser;
}

bool ProbeFunction::ParseArguments(const base::Value::Dict& arguments) {
  arguments_ = arguments.Clone();
  auto arguments_clone = arguments.Clone();
  bool success = true;
  for (const auto& [field_name, parser] : argument_parsers_) {
    auto value = arguments_clone.Extract(field_name);
    std::string err;
    if (parser->Parse(value, err)) {
      continue;
    }
    success = false;
    LOG(ERROR) << "ProbeFunction \"" << GetFunctionName()
               << "\" failed to parse argument \"" << field_name
               << "\": " << err;
  }
  if (!arguments_clone.empty()) {
    success = false;
    for (const auto& [field_name, unused_value] : arguments_clone) {
      LOG(ERROR) << "ProbeFunction \"" << GetFunctionName()
                 << "\" got unexpected argument \"" << field_name << "\"";
    }
  }
  return success ? PostParseArguments() : false;
}

bool PrivilegedProbeFunction::InvokeHelper(std::string* result) const {
  base::Value::Dict probe_statement;
  probe_statement.Set(GetFunctionName(), arguments().Clone());
  std::string probe_statement_str;
  base::JSONWriter::Write(probe_statement, &probe_statement_str);

  return Context::Get()->helper_invoker()->Invoke(
      /*probe_function=*/this, probe_statement_str, result);
}

std::optional<base::Value> PrivilegedProbeFunction::InvokeHelperToJSON() const {
  std::string raw_output;
  if (!InvokeHelper(&raw_output)) {
    LOG(ERROR) << "Failed to invoke helper.";
    return std::nullopt;
  }

  auto json_output = base::JSONReader::Read(raw_output);
  if (!json_output) {
    LOG(ERROR) << "Failed to parse output into json format.";
    VLOG(3) << "InvokeHelper raw output:\n" << raw_output;
    return std::nullopt;
  }

  return json_output;
}

int PrivilegedProbeFunction::EvalInHelper(std::string* output) const {
  DLOG(INFO) << "Invoking probe function \"" << GetFunctionName()
             << "\" in helper.";
  base::Value result{EvalImpl()};
  if (base::JSONWriter::Write(result, output))
    return 0;
  LOG(ERROR) << "Failed to serialize probed result to json string";
  return -1;
}

PrivilegedProbeFunction::DataType PrivilegedProbeFunction::Eval() const {
  auto json_output = InvokeHelperToJSON();
  if (!json_output) {
    return {};
  }
  if (!json_output->is_list()) {
    LOG(ERROR) << "Failed to parse json output as list.";
    VLOG(3) << "InvokeHelper output:\n" << *json_output;
    return {};
  }

  DataType result = std::move(json_output->GetList());
  PostHelperEvalImpl(&result);
  VLOG(3) << GetFunctionName() << " Eval output:\n" << result;
  return result;
}

}  // namespace runtime_probe
