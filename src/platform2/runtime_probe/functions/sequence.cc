// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/sequence.h"

#include <utility>

#include <base/logging.h>

namespace runtime_probe {

SequenceFunction::DataType SequenceFunction::EvalImpl() const {
  base::Value result(base::Value::Type::DICT);
  auto& result_dict = result.GetDict();

  for (const auto& func : functions_) {
    const auto& probe_results = func->Eval();

    if (probe_results.size() == 0)
      return {};

    if (probe_results.size() > 1) {
      LOG(ERROR) << "Subfunction call generates more than one results.";
      return {};
    }

    result_dict.Merge(probe_results[0].GetDict().Clone());
  }

  DataType results;
  results.Append(std::move(result));
  return results;
}

}  // namespace runtime_probe
