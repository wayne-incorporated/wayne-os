// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/util/template.h"

#include <string>
#include <utility>

namespace faced {
namespace {

// Test TupleOrSingleton returns the correct type as expected.
static_assert(std::is_same<TupleOrSingleton<int>::type, int>::value);
static_assert(std::is_same<TupleOrSingleton<int, float>::type,
                           std::tuple<int, float>>::value);
static_assert(std::is_same<TupleOrSingleton<int, float, std::string>::type,
                           std::tuple<int, float, std::string>>::value);

}  // namespace
}  // namespace faced
