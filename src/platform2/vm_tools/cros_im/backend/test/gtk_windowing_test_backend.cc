// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

#include <xkbcommon/xkbcommon-keysyms.h>

namespace cros_im {
namespace test {

BACKEND_TEST(GtkPopoverWindowTest, CommitString) {
  ExpectCreateTextInput<0>();
  ExpectCreateTextInput<1>();

  Expect<0>(Request::kActivate);
  SendCommitString<0>("ツ");
  Expect<0>(Request::kDeactivate);
  Expect<1>(Request::kActivate);
  Expect<1>(Request::kReset);

  SendCommitString<1>("ü");
  Expect<1>(Request::kDeactivate);
  Expect<0>(Request::kActivate);

  SendCommitString<0>(":)");

  Expect<1>(Request::kReset);
  Expect<0>(Request::kDeactivate);
  Expect<0>(Request::kReset);
}

}  // namespace test
}  // namespace cros_im
