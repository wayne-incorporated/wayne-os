// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_PROBE_RESULT_CHECKER_H_
#define RUNTIME_PROBE_PROBE_RESULT_CHECKER_H_

#include "runtime_probe/field_converter.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/values.h>
#include <gtest/gtest.h>

namespace runtime_probe {

class ProbeResultChecker {
 public:
  static std::unique_ptr<ProbeResultChecker> FromValue(
      const base::Value& value);

  virtual bool Apply(base::Value* probe_result) const = 0;

  virtual ~ProbeResultChecker() = default;
};

// Holds |expect| attribute of a |ProbeStatement|.
//
// |expect| attribute should be a |Value| with following format:
// {
//   <key_of_probe_result>: [<required:bool>, <expected_type:string>,
//                           <optional_validate_rule:string>]
// }
//
// Currently, we support the following expected types:
// - "int"  (use |IntegerFieldConverter|)
// - "hex"  (use |HexFieldConverter|)
// - "double"  (use |DoubleFieldConverter|)
// - "str"  (use |StringFieldConverter|)
//
// |ProbeResultChecker| will first try to convert each field to |expected_type|.
// Then, if |optional_validate_rule| is given, will check if converted value
// match the rule.
//
// TODO(b/121354690): Handle |optional_validate_rule|.
class ProbeResultCheckerDict : public ProbeResultChecker {
 public:
  static std::unique_ptr<ProbeResultCheckerDict> FromValue(
      const base::Value& dict_value);

  // Apply |expect| rules to |probe_result|
  //
  // @return |true| if all required fields are converted successfully.
  bool Apply(base::Value* probe_result) const override;

 private:
  std::map<std::string, std::unique_ptr<FieldConverter>> required_fields_;
  std::map<std::string, std::unique_ptr<FieldConverter>> optional_fields_;

  FRIEND_TEST(ProbeResultCheckerDictTest, TestFromValue);
  FRIEND_TEST(ProbeResultCheckerListTest, TestFromValue);
};

class ProbeResultCheckerList : public ProbeResultChecker {
 public:
  static std::unique_ptr<ProbeResultCheckerList> FromValue(
      const base::Value& list_value);

  // Apply |expect| rules to |probe_result|
  //
  // @return |true| if all required fields are converted successfully.
  bool Apply(base::Value* probe_result) const override;

 private:
  std::vector<std::unique_ptr<ProbeResultChecker>> checkers;

  FRIEND_TEST(ProbeResultCheckerListTest, TestFromValue);
  FRIEND_TEST(ProbeResultCheckerListTest, TestApply);
  FRIEND_TEST(ProbeResultCheckerListTest, TestApplyShortCircuit);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_PROBE_RESULT_CHECKER_H_
