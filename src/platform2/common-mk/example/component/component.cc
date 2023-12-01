// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stdio.h>

#include "component/subcomponent/subcomponent.h"

__attribute__((visibility("default"))) int component() {
  printf(__FILE__ ": COMPONENT CALLED\n");
  subcomponent();
  return 0;
}
