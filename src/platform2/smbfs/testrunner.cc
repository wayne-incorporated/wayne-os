// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/test/test_timeouts.h>
#include <brillo/test_helpers.h>
#include <mojo/core/embedder/embedder.h>

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  SetUpTests(&argc, argv, true);
  TestTimeouts::Initialize();

  mojo::core::Init();
  return RUN_ALL_TESTS();
}
