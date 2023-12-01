// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "vm_tools/concierge/if_method_exists.h"

#include <gtest/gtest.h>

namespace vm_tools {
namespace concierge {
namespace {
struct WithOwnerId {
  int owner_id() const { return 42; }
  bool owner_id_called{false};
};

struct WithOutOwnerId {
  bool owner_id_called{false};
};

template <class T>
bool MaybeProcessOwnerId(T& request) {
  if constexpr (kHasOwnerId<T>) {
    request.owner_id_called = true;
    return true;
  }
  return false;
}

TEST(IfFunctionExists, WithOwnerId) {
  WithOwnerId with;
  MaybeProcessOwnerId(with);
  ASSERT_EQ(with.owner_id_called, true);
}

TEST(IfFunctionExists, WithOutOwnerId) {
  WithOutOwnerId without;
  MaybeProcessOwnerId(without);
  ASSERT_EQ(without.owner_id_called, false);
}

}  // namespace
}  // namespace concierge
}  // namespace vm_tools
