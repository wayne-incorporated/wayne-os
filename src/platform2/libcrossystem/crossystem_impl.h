// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCROSSYSTEM_CROSSYSTEM_IMPL_H_
#define LIBCROSSYSTEM_CROSSYSTEM_IMPL_H_

#include <string>

#include <brillo/brillo_export.h>
#include <libcrossystem/crossystem_vboot_interface.h>

namespace crossystem {

// An implementation that invokes the corresponding functions provided
// in vboot/crossystem.h.
class BRILLO_EXPORT CrossystemImpl : public CrossystemVbootInterface {
 public:
  std::optional<int> VbGetSystemPropertyInt(
      const std::string& name) const override;

  bool VbSetSystemPropertyInt(const std::string& name, int value) override;

  std::optional<std::string> VbGetSystemPropertyString(
      const std::string& name) const override;

  bool VbSetSystemPropertyString(const std::string& name,
                                 const std::string& value) override;
};

}  // namespace crossystem

#endif  // LIBCROSSYSTEM_CROSSYSTEM_IMPL_H_
