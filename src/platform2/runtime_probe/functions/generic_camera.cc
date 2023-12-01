// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iterator>
#include <utility>

#include "runtime_probe/functions/generic_camera.h"

namespace runtime_probe {
namespace {

void ConcatenateDataType(GenericCameraFunction::DataType* dest,
                         GenericCameraFunction::DataType&& src) {
  for (auto& value : src) {
    dest->Append(std::move(value));
  }
}
}  // namespace

bool GenericCameraFunction::PostParseArguments() {
  usb_prober_ = GetUsbProber(base::Value::Dict{});
  mipi_prober_ = GetMipiProber(base::Value::Dict{});

  return usb_prober_ && mipi_prober_;
}

GenericCameraFunction::DataType GenericCameraFunction::EvalImpl() const {
  DataType result{};
  ConcatenateDataType(&result, usb_prober_->Eval());
  ConcatenateDataType(&result, mipi_prober_->Eval());
  return result;
}

}  // namespace runtime_probe
