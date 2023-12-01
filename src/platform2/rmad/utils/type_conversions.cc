// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/type_conversions.h"

namespace rmad {

bool ConvertFromValue(const base::Value* data, bool* result) {
  if (!data || !data->is_bool()) {
    return false;
  }
  if (result) {
    *result = data->GetBool();
  }
  return true;
}

bool ConvertFromValue(const base::Value* data, int* result) {
  if (!data || !data->is_int()) {
    return false;
  }
  if (result) {
    *result = data->GetInt();
  }
  return true;
}

bool ConvertFromValue(const base::Value* data, double* result) {
  if (!data || !data->is_double()) {
    return false;
  }
  if (result) {
    *result = data->GetDouble();
  }
  return true;
}

bool ConvertFromValue(const base::Value* data, std::string* result) {
  if (!data || !data->is_string()) {
    return false;
  }
  if (result) {
    *result = data->GetString();
  }
  return true;
}

}  // namespace rmad
