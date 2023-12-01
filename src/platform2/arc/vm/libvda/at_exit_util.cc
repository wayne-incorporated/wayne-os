// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>

namespace arc {
namespace {

__attribute__((constructor)) void CreateAtExitManager() {
  static base::AtExitManager at_exit;
}

}  // namespace
}  // namespace arc
