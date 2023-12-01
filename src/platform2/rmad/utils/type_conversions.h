// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Functions for conversion between C++ types and base::Value type.
// - base::Value ConvertToValue(const T&)
// - bool ConvertFromValue(const base::Value*, T* result)
//
// Supported types
// T = bool | int | double | std::string |
//     std::vector<T> | std::map<std::string, T>

#ifndef RMAD_UTILS_TYPE_CONVERSIONS_H_
#define RMAD_UTILS_TYPE_CONVERSIONS_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/values.h>
#include <base/strings/string_number_conversions.h>

namespace rmad {

// Convert the input type to base::Value. The input type should be supported
// by base::Value (bool, int, double, string).
template <typename T>
base::Value ConvertToValue(const T& value) {
  return base::Value(value);
}

// Convert a vector to base::Value. The vector type should be supported
// by base::Value (bool, int, double, string) or vector/map of these types.
template <typename T>
base::Value ConvertToValue(const std::vector<T>& values) {
  base::Value::List list;
  for (const auto& value : values) {
    list.Append(ConvertToValue(value));
  }
  return base::Value(std::move(list));
}

// Convert a map to base::Value. The value type should be supported by
// base::Value (bool, int, double, string) or vector/map of these types.
// TODO(chenghan): Support more types, e.g. unordered_map.
template <typename T>
base::Value ConvertToValue(const std::map<std::string, T>& values) {
  base::Value::Dict dict;
  for (const auto& [key, value] : values) {
    dict.Set(key, ConvertToValue(value));
  }
  return base::Value(std::move(dict));
}

// Convert a map to base::Value. The value type should be supported by
// base::Value (bool, int, double, string) or vector/map of these types.
// TODO(chenghan): Support more types, e.g. unordered_map.
template <typename T>
base::Value ConvertToValue(const std::map<int, T>& values) {
  base::Value::Dict dict;
  for (const auto& [key, value] : values) {
    dict.Set(base::NumberToString(key), ConvertToValue(value));
  }
  return base::Value(std::move(dict));
}

// Covert a base::Value to basic types (bool, int, double, string).
// Returns true on success, otherwise returns false.
bool ConvertFromValue(const base::Value* data, bool* result);
bool ConvertFromValue(const base::Value* data, int* result);
bool ConvertFromValue(const base::Value* data, double* result);
bool ConvertFromValue(const base::Value* data, std::string* result);

// Covert a base::Value to vector. The vector type should be supported
// by base::Value (bool, int, double, string) or vector/map of these types.
template <typename T>
bool ConvertFromValue(const base::Value* data, std::vector<T>* result) {
  if (!data || !data->is_list()) {
    return false;
  }
  std::vector<T> r;
  for (const auto& child_data : data->GetList()) {
    if (T child_result; ConvertFromValue(&child_data, &child_result)) {
      r.push_back(child_result);
    } else {
      return false;
    }
  }
  if (result) {
    *result = std::move(r);
  }
  return true;
}

// Covert a base::Value to map. The map type should be supported
// by base::Value (bool, int, double, string) or vector/map of these types.
template <typename T>
bool ConvertFromValue(const base::Value* data,
                      std::map<std::string, T>* result) {
  if (!data || !data->is_dict()) {
    return false;
  }
  std::map<std::string, T> r;
  for (const auto& [key, child_data] : data->GetDict()) {
    if (T child_result; ConvertFromValue(&child_data, &child_result)) {
      r.insert({key, child_result});
    } else {
      return false;
    }
  }
  if (result) {
    *result = std::move(r);
  }
  return true;
}

// Covert a base::Value to map. The map type should be supported
// by base::Value (bool, int, double, string) or vector/map of these types.
template <typename T>
bool ConvertFromValue(const base::Value* data, std::map<int, T>* result) {
  if (!data || !data->is_dict()) {
    return false;
  }
  std::map<int, T> r;
  for (const auto& [key_str, child_data] : data->GetDict()) {
    int key;
    T child_result;
    if (base::StringToInt(key_str, &key) &&
        ConvertFromValue(&child_data, &child_result)) {
      r.insert({key, child_result});
    } else {
      return false;
    }
  }
  if (result) {
    *result = std::move(r);
  }
  return true;
}

}  // namespace rmad

#endif  // RMAD_UTILS_TYPE_CONVERSIONS_H_
