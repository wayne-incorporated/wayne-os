// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_TAP_DEVICE_BUILDER_H_
#define VM_TOOLS_CONCIERGE_TAP_DEVICE_BUILDER_H_

#include <stdint.h>

#include <string>

#include <base/files/scoped_file.h>
#include <chromeos/patchpanel/mac_address_generator.h>

namespace vm_tools {
namespace concierge {

// Builds and configures a tap device.  If the returned ScopedFD is valid then
// the device has been properly configured.
base::ScopedFD BuildTapDevice(const patchpanel::MacAddress& mac_addr,
                              uint32_t ipv4_addr,
                              uint32_t ipv4_netmask,
                              bool vnet_hdr);

// Opens and configures a tap device.  If the returned ScopedFD is valid then
// the device has been properly configured.
// If |ifname_out| is non-null, it is populated with the final interface name.
base::ScopedFD OpenTapDevice(const std::string& ifname_in,
                             bool vnet_hdr,
                             std::string* ifname_out);

}  //  namespace concierge
}  //  namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_TAP_DEVICE_BUILDER_H_
