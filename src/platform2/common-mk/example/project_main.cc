// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stdio.h>

#include "component/component.h"

int main() {
  printf("Sup world.\n");
  component();
  printf("Goodbye world.\n");
  return 0;
}
