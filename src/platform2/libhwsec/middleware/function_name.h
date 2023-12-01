// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_MIDDLEWARE_FUNCTION_NAME_H_
#define LIBHWSEC_MIDDLEWARE_FUNCTION_NAME_H_

#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <base/no_destructor.h>
#include <brillo/type_name_undecorate.h>
#include <re2/re2.h>

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

// This function helper can help us get the function name form the function
// type.
//
// Example usage:
//   bool MagicFunction() {
//     return GetFuncName<&MagicFunction>() == "MagicFunction";
//   }  // return true;

namespace hwsec {

template <auto Func>
struct FuncWrapper {};

inline constexpr const char kFuncWrapMatchRule[] =
    R"(hwsec::FuncWrapper<&\(*((\(anonymous namespace\)|[\w:])*)[()<>])";

inline const re2::RE2& GetFuncWrapperRE() {
  static const base::NoDestructor<re2::RE2> rule(kFuncWrapMatchRule);
  return *rule;
}

template <auto Func>
inline std::string GetFuncName() {
  std::string func_name = brillo::GetUndecoratedTypeName<FuncWrapper<Func>>();
  std::string result;

  if (!re2::RE2::PartialMatch(func_name, GetFuncWrapperRE(), &result)) {
    return func_name;
  }

  return result;
}

}  // namespace hwsec

#endif  // LIBHWSEC_MIDDLEWARE_FUNCTION_NAME_H_
