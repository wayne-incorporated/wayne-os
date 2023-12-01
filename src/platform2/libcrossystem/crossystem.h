// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCROSSYSTEM_CROSSYSTEM_H_
#define LIBCROSSYSTEM_CROSSYSTEM_H_

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <brillo/brillo_export.h>
#include <libcrossystem/crossystem_impl.h>
#include <libcrossystem/crossystem_vboot_interface.h>

namespace crossystem {

// C++ class to access crossystem system properties.
class BRILLO_EXPORT Crossystem {
 public:
  // Default implementation uses the real crossystem (CrossystemImpl).
  Crossystem() : Crossystem(std::make_unique<CrossystemImpl>()) {}

  // Can be used to instantiate a fake implementation for testing by passing
  // CrossystemFake.
  explicit Crossystem(std::unique_ptr<CrossystemVbootInterface> impl)
      : impl_(std::move(impl)) {}

  std::optional<int> VbGetSystemPropertyInt(const std::string& name) const;

  bool VbSetSystemPropertyInt(const std::string& name, int value);

  std::optional<std::string> VbGetSystemPropertyString(
      const std::string& name) const;

  bool VbSetSystemPropertyString(const std::string& name,
                                 const std::string& value);

  /// Reads a system property boolean.
  ///
  /// @param name The name of the target system property.
  /// @return The property value, or |base::nullopt| if error.
  std::optional<bool> GetSystemPropertyBool(const std::string& name) const;

  /// Sets a system property boolean.
  ///
  /// @param name The name of the target system property.
  /// @param value The boolean value to set.
  /// @return |true| if it succeeds; |false| if it fails.
  bool SetSystemPropertyBool(const std::string& name, bool value);

  /// Get hardware write protect status.
  ///
  /// @note Crashes if the underlying status is not set or set to an invalid
  /// value.
  ///
  /// @return true if hardware write protect is enabled; false otherwise.
  bool HardwareWriteProtectIsEnabled() const;

  /// Get hardware ID.
  ///
  /// @return hardware ID string
  std::string GetHardwareID() const;

  /// Check if system is configured to only boot from a signed kernel.
  ///
  /// @note Crashes if the underlying status is not set or set to an invalid
  /// value.
  ///
  /// @return true if only signed kernels will boot; false otherwise.
  bool OnlyBootSignedKernel() const;

  // Use the helper methods (e.g., HardwareProtectIsEnabled()) rather than
  // using these constants directly.
  BRILLO_PRIVATE static constexpr char kHardwareWriteProtect[] = "wpsw_cur";
  BRILLO_PRIVATE static constexpr char kHardwareId[] = "hwid";
  BRILLO_PRIVATE static constexpr char kDevBootSignedOnly[] =
      "dev_boot_signed_only";

 private:
  std::unique_ptr<CrossystemVbootInterface> impl_;
};

}  // namespace crossystem

#endif  // LIBCROSSYSTEM_CROSSYSTEM_H_
