// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Example helper program. Helper programs emit their results on stdout. These
// are often run sandboxed.

#include <stdio.h>

int main() {
  printf("Hello, World!\n");
  return 0;
}
