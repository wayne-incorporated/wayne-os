// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_GENERIC_BATTERY_H_
#define RUNTIME_PROBE_FUNCTIONS_GENERIC_BATTERY_H_

#include <string>
#include <vector>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {

class GenericBattery final : public PrivilegedProbeFunction {
  // Read battery information from sysfs.
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("generic_battery");

  void PostHelperEvalImpl(DataType* result) const final;

 private:
  DataType EvalImpl() const override;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_GENERIC_BATTERY_H_
