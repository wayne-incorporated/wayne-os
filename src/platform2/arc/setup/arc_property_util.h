// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_SETUP_ARC_PROPERTY_UTIL_H_
#define ARC_SETUP_ARC_PROPERTY_UTIL_H_

#include <string>

#include <base/values.h>
#include <dbus/bus.h>

namespace base {
class FilePath;
}  // namespace base

namespace brillo {
class CrosConfigInterface;
}  // namespace brillo

namespace arc {

// Parses SOC manufacturer and model from /proc/cpuinfo and appends the results
// to |dest|. Used for x86/64 architectures. The path of /proc/cpuinfo can be
// overridden for testing purposes.
void AppendX86SocProperties(const base::FilePath& cpuinfo_path,
                            std::string* dest);

// Tries to detect the SoC manufacturer and model given the socinfo directory
// in Linux sysfs. Should be passed a path to the directory
// /sys/bus/soc/devices which can be overridden for testing.
// Appends results to |dest|. Used for ARM architectures.
void AppendArmSocProperties(const base::FilePath& sysfs_socinfo_devices_path,
                            brillo::CrosConfigInterface* config,
                            std::string* dest);

// Expands the contents of a template Android property file.  Strings like
// {property} will be looked up in |config| and replaced with their values.
// Returns true if all {} strings were successfully expanded, or false if any
// properties were not found.
bool ExpandPropertyContentsForTesting(const std::string& content,
                                      brillo::CrosConfigInterface* config,
                                      bool debuggable,
                                      std::string* expanded_content);

// Truncates the value side of an Android key=val property line, including
// handling the special case of build fingerprint.
bool TruncateAndroidPropertyForTesting(const std::string& line,
                                       std::string* truncated);

// Expands properties (i.e. {property-name}) in |input| with the dictionary
// |config| provides, and writes the results to |output|. Returns true if the
// output file is successfully written.
bool ExpandPropertyFileForTesting(const base::FilePath& input,
                                  const base::FilePath& output,
                                  brillo::CrosConfigInterface* config);

// Calls ExpandPropertyFile for {build,default,vendor_build}.prop files in
// |source_path|. Expanded files are written in |dest_path|. Returns true on
// success. When |single_file| is true, only one file (|dest_path| itself) is
// written. All expanded properties are included in the single file.
// When |add_native_bridge_64_bit_support| is true, add / modify some properties
// related to supported CPU ABIs. |hw_oemcrypto_support| uses D-Bus to talk to
// the cdm-oemcrypto daemon and add specific properties needed by the Android
// CDM when we are using HW based DRM. |debuggable| is used to populate
// ro.debuggable property. |bus| is used for D-Bus communication when
// |hw_oemcrypto_support| is true.
bool ExpandPropertyFiles(const base::FilePath& source_path,
                         const base::FilePath& dest_path,
                         bool single_file,
                         bool hw_oemcrypto_support,
                         bool include_soc_props,
                         bool debuggable,
                         scoped_refptr<::dbus::Bus> bus);

}  // namespace arc

#endif  // ARC_SETUP_ARC_PROPERTY_UTIL_H_
