// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/crossystem_impl.h"

#include <vboot/crossystem.h>

int CrossystemImpl::VbGetSystemPropertyInt(const char* name) {
  return ::VbGetSystemPropertyInt(name);
}

int CrossystemImpl::VbSetSystemPropertyInt(const char* name, int value) {
  return ::VbSetSystemPropertyInt(name, value);
}

const char* CrossystemImpl::VbGetSystemPropertyString(const char* name,
                                                      char* dest,
                                                      std::size_t size) {
  return ::VbGetSystemPropertyString(name, dest, size);
}

int CrossystemImpl::VbSetSystemPropertyString(const char* name,
                                              const char* value) {
  return ::VbSetSystemPropertyString(name, value);
}
