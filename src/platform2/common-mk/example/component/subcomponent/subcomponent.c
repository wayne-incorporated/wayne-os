/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include <stdio.h>

__attribute__((visibility("default"))) int subcomponent() {
  printf(__FILE__ ": SUBCOMPONENT CALLED\n");
  return 0;
}
