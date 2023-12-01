// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_SEQUENCE_H_
#define RUNTIME_PROBE_FUNCTIONS_SEQUENCE_H_

#include <memory>
#include <vector>

#include <base/values.h>
#include <gtest/gtest.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {

// Execute multiple probe functions sequentially and merge their outputs.
//
// Each subfunction must create one result, it will be merged to previous
// results.  If there are common keys, the later one will override previous one.
//
// For example, function_1 and function_2 outputs the following respectively::
//   { "a": true, "common": false }
//   { "b": true, "common": true }
//
// The final result will be { "a": true, "b": true, "common": true }
//
// If any subfunction returns 0 or more than 1 results, the final result will be
// empty (vector size will be empty).
class SequenceFunction : public ProbeFunction {
  using ProbeFunction::ProbeFunction;

 public:
  NAME_PROBE_FUNCTION("sequence");

 private:
  DataType EvalImpl() const override;

  PROBE_FUNCTION_ARG_DEF(std::vector<std::unique_ptr<ProbeFunction>>,
                         functions);

  FRIEND_TEST(SequenceFunctionTest, TestEvalFailTooManyResults);
  FRIEND_TEST(SequenceFunctionTest, TestEvalSuccess);
  FRIEND_TEST(SequenceFunctionTest, TestParserEmptyList);
  FRIEND_TEST(SequenceFunctionTest, TestParseFunctions);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_SEQUENCE_H_
