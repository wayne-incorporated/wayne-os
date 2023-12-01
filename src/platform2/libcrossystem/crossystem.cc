// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libcrossystem/crossystem.h>

#include <base/check_op.h>
#include <optional>

namespace crossystem {

std::optional<int> Crossystem::VbGetSystemPropertyInt(
    const std::string& name) const {
  return impl_->VbGetSystemPropertyInt(name);
}

bool Crossystem::VbSetSystemPropertyInt(const std::string& name, int value) {
  return impl_->VbSetSystemPropertyInt(name, value);
}

std::optional<std::string> Crossystem::VbGetSystemPropertyString(
    const std::string& name) const {
  return impl_->VbGetSystemPropertyString(name);
}

bool Crossystem::VbSetSystemPropertyString(const std::string& name,
                                           const std::string& value) {
  return impl_->VbSetSystemPropertyString(name, value);
}

std::optional<bool> Crossystem::GetSystemPropertyBool(
    const std::string& name) const {
  std::optional<int> value = VbGetSystemPropertyInt(name);
  if (!value.has_value()) {
    return std::nullopt;
  }
  CHECK_GE(*value, 0);
  return *value != 0;
}

bool Crossystem::SetSystemPropertyBool(const std::string& name, bool value) {
  return VbSetSystemPropertyInt(name, value);
}

bool Crossystem::HardwareWriteProtectIsEnabled() const {
  std::optional<bool> ret = GetSystemPropertyBool(kHardwareWriteProtect);
  CHECK(ret.has_value());
  return *ret;
}

std::string Crossystem::GetHardwareID() const {
  std::optional<std::string> ret = VbGetSystemPropertyString(kHardwareId);
  CHECK(ret.has_value());
  return *ret;
}

bool Crossystem::OnlyBootSignedKernel() const {
  std::optional<bool> ret = GetSystemPropertyBool(kDevBootSignedOnly);
  CHECK(ret.has_value());
  return *ret;
}

}  // namespace crossystem
