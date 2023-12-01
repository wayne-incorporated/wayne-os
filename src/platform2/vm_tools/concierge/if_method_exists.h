// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_IF_METHOD_EXISTS_H_
#define VM_TOOLS_CONCIERGE_IF_METHOD_EXISTS_H_

#include <type_traits>
namespace vm_tools {
namespace concierge {

// Check if a method exists within a class. The default template evaluates to
// false but when &T::method can compile, the value |CONDITION_NAME<class>| will
// evaluate to true.
#define METHOD_EXISTS_HELPER(CONDITION, CONDITION_NAME) \
  template <typename T, typename = void>                \
  constexpr bool CONDITION_NAME = false;                \
  template <typename T>                                 \
  constexpr bool CONDITION_NAME<T, std::void_t<decltype(CONDITION)>> = true

METHOD_EXISTS_HELPER(&T::owner_id, kHasOwnerId);
METHOD_EXISTS_HELPER(&T::cryptohome_id, kHasCryptohomeId);
METHOD_EXISTS_HELPER(&T::name, kHasName);
METHOD_EXISTS_HELPER(&T::vm_name, kHasVmName);
METHOD_EXISTS_HELPER(&T::failure_reason, kHasFailureReason);
METHOD_EXISTS_HELPER(&T::reason, kHasReason);
#undef METHOD_EXISTS_HELPER
}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_IF_METHOD_EXISTS_H_
