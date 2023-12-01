/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_VALUE_UTIL_H_
#define CAMERA_HAL_FAKE_VALUE_UTIL_H_

#include <string>
#include <vector>

#include <base/values.h>

namespace cros {
struct DottedPath {
  std::vector<std::string> segments;

  DottedPath extend(const std::string& p) const;
};

std::ostream& operator<<(std::ostream& s, const DottedPath& path);

template <typename T>
struct WithPath {
  const T* value;
  DottedPath path;

  const T* operator->() const { return value; }
  const T& operator*() const { return *value; }
};

typedef WithPath<base::Value> ValueWithPath;
typedef WithPath<base::Value::List> ListWithPath;
typedef WithPath<base::Value::Dict> DictWithPath;

template <>
struct WithPath<base::Value::List> {
  struct Iterator {
    const DottedPath& path;
    const base::Value::List* value;
    size_t idx;
    const Iterator& operator++();
    ValueWithPath operator*() const;
    bool operator!=(const Iterator& o) const;
  };

  const base::Value::List* value;
  DottedPath path;

  Iterator begin() const;
  Iterator end() const;
};

std::optional<DictWithPath> GetIfDict(const ValueWithPath& v);
std::optional<ListWithPath> GetIfList(const ValueWithPath& v);

template <typename T, typename... Ts>
using is_one_of = std::disjunction<std::is_same<T, Ts>...>;

template <typename T>
using is_supported_type = is_one_of<T,
                                    int,
                                    bool,
                                    double,
                                    std::string,
                                    ValueWithPath,
                                    DictWithPath,
                                    ListWithPath>;

// Gets a value corresponds to a key from a dict. Print error and return
// nullopt if the key doesn't exist or it's not of correct type.
template <typename T,
          typename = typename std::enable_if_t<is_supported_type<T>::value>>
std::optional<T> GetRequiredValue(const DictWithPath& dict,
                                  base::StringPiece key);

// Gets a value corresponds to a key from a dict. Return nullopt if the key
// doesn't exist or it's not of correct type, but only print error if the key
// exists but is not of the correct type.
template <typename T,
          typename = typename std::enable_if_t<is_supported_type<T>::value>>
std::optional<T> GetValue(const DictWithPath& dict, base::StringPiece key);

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_VALUE_UTIL_H_
