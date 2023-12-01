// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_VPD_CACHED_H_
#define RUNTIME_PROBE_FUNCTIONS_VPD_CACHED_H_

#include <memory>
#include <string>

#include <base/values.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {

// Read cached VPD information from sysfs.
//
// System usually boots with VPD cached, we read the cached version to avoid
// the delay of accessing the flashrom. If VPD data changed after boot, this
// function will not reflect that.
//
// In this first implementation, only one argument will be taken, that is the
// key in the RO_VPD area to read.

class VPDCached : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("vpd_cached");

 private:
  DataType EvalImpl() const override;

  PROBE_FUNCTION_ARG_DEF(std::string, vpd_name);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_VPD_CACHED_H_
