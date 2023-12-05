// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MATCHERS_H_
#define LOGIN_MANAGER_MATCHERS_H_

#include <algorithm>
#include <type_traits>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

namespace login_manager {

// Forces arg to an array of char and compares to str for equality.
MATCHER_P(CastEq, str, "") {
  return std::equal(str.begin(), str.end(), reinterpret_cast<const char*>(arg));
}

MATCHER_P(VectorEq, str, "") {
  return str.size() == arg.size() &&
         std::equal(str.begin(), str.end(), arg.begin());
}

// Compares protobuf message by serialization.
MATCHER_P(ProtoEq, proto, "") {
  // Make sure given proto types are same.
  using ArgType = typename std::remove_cv<
      typename std::remove_reference<decltype(arg)>::type>::type;
  using ProtoType = typename std::remove_cv<
      typename std::remove_reference<decltype(proto)>::type>::type;
  static_assert(std::is_same<ArgType, ProtoType>::value, "Proto type mismatch");

  return arg.SerializeAsString() == proto.SerializeAsString();
}

MATCHER_P(StatusEq, status, "") {
  return (arg.owner_key_file_state == status.owner_key_file_state &&
          arg.policy_file_state == status.policy_file_state &&
          arg.defunct_prefs_file_state == status.defunct_prefs_file_state);
}

MATCHER_P(PathStartsWith, path_prefix, "") {
  return path_prefix.IsParent(arg);
}

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MATCHERS_H_
