// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/crossystem_utils_impl.h"

#include <string>

#include <vboot/crossystem.h>

namespace rmad {

bool CrosSystemUtilsImpl::SetInt(const std::string& key, int value) {
  return ::VbSetSystemPropertyInt(key.c_str(), value) == 0;
}

bool CrosSystemUtilsImpl::GetInt(const std::string& key, int* value) const {
  int result = ::VbGetSystemPropertyInt(key.c_str());
  if (result == -1) {
    return false;
  }
  *value = result;
  return true;
}

bool CrosSystemUtilsImpl::SetString(const std::string& key,
                                    const std::string& value) {
  return ::VbSetSystemPropertyString(key.c_str(), value.c_str()) == 0;
}

bool CrosSystemUtilsImpl::GetString(const std::string& key,
                                    std::string* value) const {
  char buf[VB_MAX_STRING_PROPERTY];
  if (::VbGetSystemPropertyString(key.c_str(), buf, sizeof(buf)) != 0) {
    return false;
  }
  *value = std::string(buf);
  return true;
}

}  // namespace rmad
