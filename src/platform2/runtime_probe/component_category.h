// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_COMPONENT_CATEGORY_H_
#define RUNTIME_PROBE_COMPONENT_CATEGORY_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/values.h>
#include <gtest/gtest.h>

#include "runtime_probe/probe_statement.h"

namespace runtime_probe {

class ComponentCategory {
  // A component category is defined in following format:
  //
  // {
  //   <component_name:string>: <statement:ProbeStatement>,
  //   ...
  // }
 public:
  // Factory method that creates the component category from the given
  // dictionary.
  // Return |nullptr| if loading fails.
  static std::unique_ptr<ComponentCategory> FromValue(
      const std::string& category_name, const base::Value& dv);

  virtual ~ComponentCategory() = default;

  // Evaluates this category and return a base::Value::List.
  virtual base::Value::List Eval() const;

  // Gets all component names of this category.
  std::vector<std::string> GetComponentNames() const;

  // Returns an iterator to the first component.
  auto begin() { return component_.begin(); }
  auto begin() const { return component_.begin(); }
  auto cbegin() const { return component_.cbegin(); }

  // Returns an iterator following the last component.
  auto end() { return component_.end(); }
  auto end() const { return component_.end(); }
  auto cend() const { return component_.cend(); }

  // Set |probe_statement| with the component name |component_name| for testing.
  void SetComponentForTesting(std::string component_name,
                              std::unique_ptr<ProbeStatement> probe_statement) {
    component_[component_name] = std::move(probe_statement);
  }

 private:
  std::string category_name_;
  std::map<std::string, std::unique_ptr<ProbeStatement>> component_;

  FRIEND_TEST(ProbeConfigTest, LoadConfig);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_COMPONENT_CATEGORY_H_
