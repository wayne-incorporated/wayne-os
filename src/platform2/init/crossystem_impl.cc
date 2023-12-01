// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/crossystem_impl.h"

#include <string>

#include <vboot/crossystem.h>

bool CrosSystemImpl::GetInt(const std::string& name, int* value_out) {
  int value = ::VbGetSystemPropertyInt(name.c_str());
  if (value == -1)
    return false;
  *value_out = value;
  return true;
}

bool CrosSystemImpl::SetInt(const std::string& name, int value) {
  return 0 == ::VbSetSystemPropertyInt(name.c_str(), value);
}

bool CrosSystemImpl::GetString(const std::string& name,
                               std::string* value_out) {
  char buf[VB_MAX_STRING_PROPERTY];
  if (::VbGetSystemPropertyString(name.c_str(), buf, sizeof(buf)) != 0)
    return false;
  *value_out = std::string(buf);
  return true;
}

bool CrosSystemImpl::SetString(const std::string& name,
                               const std::string& value) {
  return 0 == ::VbSetSystemPropertyString(name.c_str(), value.c_str());
}
