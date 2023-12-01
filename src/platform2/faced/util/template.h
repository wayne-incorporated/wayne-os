// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_TEMPLATE_H_
#define FACED_UTIL_TEMPLATE_H_

#include <tuple>
#include <utility>

namespace faced {

// Given a parameter pack, return:
//
//   * An error if the pack is empty;
//   * Type T if the pack is a single type T
//   * Type std::tuple<T...> if the pack is two or more types.
//
// For example:
//
//   TupleOrSingleton<int>::type         == int
//   TupleOrSingleton<int, float>::type  == std::tuple<int, float>
//   TupleOrSingleton<>::type            == <compile-time error>
//
template <typename... Args>
using TupleOrSingleton = typename std::conditional<
    (sizeof...(Args) == 1),
    typename std::tuple_element<0, std::tuple<Args...>>::type,
    typename std::tuple<Args...>>;

}  // namespace faced

#endif  // FACED_UTIL_TEMPLATE_H_
