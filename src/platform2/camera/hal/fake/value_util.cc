/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <string>
#include <vector>

#include <base/strings/string_util.h>
#include <base/strings/string_number_conversions.h>

#include "cros-camera/common.h"
#include "hal/fake/value_util.h"

namespace cros {

DottedPath DottedPath::extend(const std::string& p) const {
  DottedPath ret = *this;
  ret.segments.push_back(p);
  return ret;
}

std::ostream& operator<<(std::ostream& s, const DottedPath& path) {
  s << "$";
  for (const auto& p : path.segments) {
    s << "." << p;
  }
  return s;
}

const ListWithPath::Iterator& ListWithPath::Iterator::operator++() {
  idx++;
  return *this;
}

ValueWithPath ListWithPath::Iterator::operator*() const {
  return ValueWithPath{&(*value)[idx], path.extend(base::NumberToString(idx))};
}

bool ListWithPath::Iterator::operator!=(const Iterator& o) const {
  return idx != o.idx;
}

ListWithPath::Iterator ListWithPath::begin() const {
  return Iterator{path, value, 0};
}

ListWithPath::Iterator ListWithPath::end() const {
  return Iterator{path, value, value->size()};
}

#define WARN_MALFORMED(path, type, value)                        \
  LOGF(WARNING) << "malformed entry at " << path << ": " << type \
                << " expected, got:\n"                           \
                << value
#define WARN_MISSING(path) LOGF(WARNING) << "missing required key at " << path
#define WARN_MISSING_WITH_TYPE(path, type) \
  WARN_MISSING(path) << ": " << type << " expected"

std::optional<DictWithPath> GetIfDict(const ValueWithPath& v) {
  auto ret = v->GetIfDict();
  if (ret == nullptr) {
    WARN_MALFORMED(v.path, "dictionary", *v.value);
    return std::nullopt;
  }
  return DictWithPath{ret, v.path};
}

std::optional<ListWithPath> GetIfList(const ValueWithPath& v) {
  auto ret = v->GetIfList();
  if (ret == nullptr) {
    WARN_MALFORMED(v.path, "list", *v.value);
    return std::nullopt;
  }
  return ListWithPath{ret, v.path};
}

template <>
std::optional<ValueWithPath> GetValue<ValueWithPath>(const DictWithPath& dict,
                                                     base::StringPiece key) {
  auto child = dict->Find(key);
  if (child == nullptr) {
    return std::nullopt;
  }
  return ValueWithPath{child, dict.path.extend(std::string(key))};
}

template <>
std::optional<ValueWithPath> GetRequiredValue<ValueWithPath>(
    const DictWithPath& dict, base::StringPiece key) {
  auto val = GetValue<ValueWithPath>(dict, key);
  if (!val.has_value()) {
    WARN_MISSING(dict.path << "." << key);
  }
  return val;
}

#define GENERATE_TYPED_GETTER(c_type, value_type, type_name, return_wrapper) \
  template <>                                                                \
  std::optional<c_type> GetRequiredValue<c_type>(const DictWithPath& dict,   \
                                                 base::StringPiece key) {    \
    auto child = dict->Find(key);                                            \
    if (child == nullptr) {                                                  \
      WARN_MISSING_WITH_TYPE(dict.path << "." << key, #type_name);           \
      return std::nullopt;                                                   \
    }                                                                        \
    auto ret = child->GetIf##value_type();                                   \
    if (!ret) {                                                              \
      WARN_MALFORMED(dict.path << "." << key, #type_name, *child);           \
      return std::nullopt;                                                   \
    }                                                                        \
    return return_wrapper(ret, dict.path.extend(std::string(key)));          \
  }                                                                          \
                                                                             \
  template <>                                                                \
  std::optional<c_type> GetValue<c_type>(const DictWithPath& dict,           \
                                         base::StringPiece key) {            \
    auto child = dict->Find(key);                                            \
    if (child == nullptr) {                                                  \
      return std::nullopt;                                                   \
    }                                                                        \
    auto ret = child->GetIf##value_type();                                   \
    if (!ret) {                                                              \
      WARN_MALFORMED(dict.path << "." << key, #type_name, *child);           \
      return std::nullopt;                                                   \
    }                                                                        \
    return return_wrapper(ret, dict.path.extend(std::string(key)));          \
  }

#define DEREF_RET(x, y) *x
#define DICT_WITH_PATH_WRAPPER(x, y) \
  DictWithPath { x, y }
#define LIST_WITH_PATH_WRAPPER(x, y) \
  ListWithPath { x, y }

GENERATE_TYPED_GETTER(int, Int, integer, DEREF_RET);
GENERATE_TYPED_GETTER(bool, Bool, boolean, DEREF_RET);
GENERATE_TYPED_GETTER(double, Double, number, DEREF_RET);
GENERATE_TYPED_GETTER(std::string, String, string, DEREF_RET);
GENERATE_TYPED_GETTER(DictWithPath, Dict, dict, DICT_WITH_PATH_WRAPPER);
GENERATE_TYPED_GETTER(ListWithPath, List, list, LIST_WITH_PATH_WRAPPER);

#undef LIST_WITH_PATH_WRAPPER
#undef DICT_WITH_PATH_WRAPPER
#undef DEREF_RET
#undef GENERATE_TYPED_GETTER
#undef WARN_MISSING_WITH_TYPE
#undef WARN_MISSING
#undef WARN_MALFORMED
}  // namespace cros
