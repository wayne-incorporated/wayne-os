// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_PROBE_FUNCTION_ARGUMENT_H_
#define RUNTIME_PROBE_PROBE_FUNCTION_ARGUMENT_H_

#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/values.h>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {
namespace internal {

// Type templates for identifying probe function argument type.
template <typename>
inline constexpr bool IsProbeFunctionArg = false;
template <>
inline constexpr bool IsProbeFunctionArg<std::string> = true;
template <>
inline constexpr bool IsProbeFunctionArg<bool> = true;
template <>
inline constexpr bool IsProbeFunctionArg<double> = true;
template <>
inline constexpr bool IsProbeFunctionArg<int> = true;
template <>
inline constexpr bool IsProbeFunctionArg<std::unique_ptr<ProbeFunction>> = true;

template <typename T>
bool ParseArgumentImpl(const base::Value& value, T& out, std::string& err);

template <typename T>
bool ParseListArgument(const base::Value& value,
                       std::vector<T>& out,
                       std::string& err) {
  static_assert(IsProbeFunctionArg<T>, "Unsupport type");

  if (!value.is_list()) {
    std::stringstream ss;
    ss << "expected a list but got: " << value;
    err = ss.str();
    return false;
  }

  std::vector<T> tmp_list;
  for (const auto& v : value.GetList()) {
    T tmp;
    if (!ParseArgumentImpl(v, tmp, err)) {
      err = "failed to parse list: " + err;
      return false;
    }
    tmp_list.push_back(std::move(tmp));
  }
  out = std::move(tmp_list);
  return true;
}

// Type templates for identifying the vector.
template <typename>
inline constexpr bool IsVector = false;
template <typename T>
inline constexpr bool IsVector<std::vector<T>> = true;

template <typename T>
bool ParseArgument(const base::Value& value, T& out, std::string& err) {
  if constexpr (IsVector<T>) {
    return ParseListArgument(value, out, err);
  } else {
    static_assert(IsProbeFunctionArg<T>, "Unsupport type");
    return ParseArgumentImpl(value, out, err);
  }
}

}  // namespace internal

// Provides a ArgumentParser to parse argument to |target|.
template <typename T>
class ArgumentParserProvider : public ProbeFunction::ArgumentParser {
 public:
  ArgumentParserProvider(ProbeFunction* probe_function,
                         const std::string& field_name,
                         T& target,
                         std::optional<T> default_value = std::nullopt)
      : target_(target), default_value_(std::move(default_value)) {
    probe_function->RegisterArgumentParser(field_name, this);
  }
  ArgumentParserProvider(const ArgumentParserProvider&) = delete;
  ArgumentParserProvider& operator=(const ArgumentParserProvider&) = delete;
  ~ArgumentParserProvider() override = default;

  bool Parse(const std::optional<base::Value>& value,
             std::string& err) override {
    if (value.has_value()) {
      return internal::ParseArgument(value.value(), target_, err);
    }
    if (default_value_.has_value()) {
      target_ = std::move(default_value_.value());
      return true;
    }
    err = "field is required but was not found";
    return false;
  }

 private:
  T& target_;
  std::optional<T> default_value_;
};

// Same as above but |target| is std::optional<T>. Will set to |std::nullopt| if
// argument is missing.
template <typename T>
class ArgumentParserProvider<std::optional<T>>
    : public ProbeFunction::ArgumentParser {
 public:
  ArgumentParserProvider(ProbeFunction* probe_function,
                         const std::string& field_name,
                         std::optional<T>& target)
      : target_(target) {
    probe_function->RegisterArgumentParser(field_name, this);
  }
  ArgumentParserProvider(const ArgumentParserProvider&) = delete;
  ArgumentParserProvider& operator=(const ArgumentParserProvider&) = delete;
  ~ArgumentParserProvider() override = default;

  bool Parse(const std::optional<base::Value>& value,
             std::string& err) override {
    if (value.has_value()) {
      T tmp;
      if (internal::ParseArgument(value.value(), tmp, err)) {
        target_ = std::move(tmp);
        return true;
      }
      return false;
    }
    target_ = std::nullopt;
    return true;
  }

 private:
  std::optional<T>& target_;
};

// Defines a probe function arguments. Should be used in a derived class of
// ProbeFunction class. This define a member variable and a
// ArgumentParserProvider to parse argument to the member variable.
//
// |type|: The type of the argument.
// |field_name|: The field name of the argument. This will define a member
//               variable |field_name_|.
// |...|: A default value. Cannot be set if |type| is std::optional<T> (because
//        it will never be nullopt).
//        If |type| is not std::optional<T> and don't have default value, the
//        argument become a required argument.
//
// Example:
//   class MyFunction: public ProbeFunction {
//    private:
//     PROBE_FUNCTION_ARG_DEF(int, a_int);
//     PROBE_FUNCTION_ARG_DEF(int, default_int, 42);
//     PROBE_FUNCTION_ARG_DEF(std::optional<int>, opt_int);
//   }
#define PROBE_FUNCTION_ARG_DEF(type, field_name, ...)                   \
  type field_name##_;                                                   \
  ArgumentParserProvider<type> field_name##_argument_parser_provider_ { \
    this, #field_name, field_name##_, ##__VA_ARGS__                     \
  }

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_PROBE_FUNCTION_ARGUMENT_H_
