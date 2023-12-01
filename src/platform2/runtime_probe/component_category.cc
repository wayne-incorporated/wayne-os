// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/component_category.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/values.h>
#include <brillo/map_utils.h>

#include "runtime_probe/probe_statement.h"

namespace runtime_probe {

std::unique_ptr<ComponentCategory> ComponentCategory::FromValue(
    const std::string& category_name, const base::Value& dv) {
  if (!dv.is_dict()) {
    LOG(ERROR) << "ComponentCategory::FromValue takes a dictionary as"
               << " parameter";
    return nullptr;
  }

  std::unique_ptr<ComponentCategory> instance{new ComponentCategory()};
  instance->category_name_ = category_name;

  for (const auto& entry : dv.GetDict()) {
    const auto& component_name = entry.first;
    const auto& value = entry.second;
    auto probe_statement = ProbeStatement::FromValue(component_name, value);
    if (!probe_statement) {
      LOG(ERROR) << "Component " << component_name
                 << " doesn't contain a valid probe statement.";
      return nullptr;
    }
    instance->component_[component_name] = std::move(probe_statement);
  }

  return instance;
}

base::Value::List ComponentCategory::Eval() const {
  base::Value::List results;

  for (const auto& entry : component_) {
    const auto& component_name = entry.first;
    const auto& probe_statement = entry.second;
    for (auto& probe_statement_dv : probe_statement->Eval()) {
      base::Value::Dict result;
      result.Set("name", component_name);
      result.Set("values", std::move(probe_statement_dv));
      auto information_dv = probe_statement->GetInformation();
      if (information_dv)
        result.Set("information", std::move(*information_dv));
      results.Append(std::move(result));
    }
  }

  return results;
}

std::vector<std::string> ComponentCategory::GetComponentNames() const {
  return brillo::GetMapKeysAsVector(component_);
}

}  // namespace runtime_probe
