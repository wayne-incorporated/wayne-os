// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An implementation of the Android native shared memory buffers, which is
// implemented on our implentation of ashmem which uses native shared memory.

// android/log.h contains __INTRODUCED_IN() macro and must be included before
// sharedmem.h
#include <android/log.h>
#include "android/sharedmem.h"

#include <cutils/ashmem.h>

int ASharedMemory_create(const char* name, size_t size) {
  return ashmem_create_region(name, size);
}

size_t ASharedMemory_getSize(int fd) {
  return ashmem_get_size_region(fd);
}

int ASharedMemory_setProt(int fd, int prot) {
  return ashmem_set_prot_region(fd, prot);
}
