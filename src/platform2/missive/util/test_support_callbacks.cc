// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/util/test_support_callbacks.h"

namespace reporting {
namespace test {

TestCallbackWaiter::TestCallbackWaiter() : signaled_cb_(cb()) {}
TestCallbackWaiter::~TestCallbackWaiter() = default;

TestCallbackAutoWaiter::TestCallbackAutoWaiter() {
  Attach();
}
TestCallbackAutoWaiter::~TestCallbackAutoWaiter() {
  Wait();
}

}  // namespace test
}  // namespace reporting
