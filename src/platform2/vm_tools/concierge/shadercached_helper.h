// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SHADERCACHED_HELPER_H_
#define VM_TOOLS_CONCIERGE_SHADERCACHED_HELPER_H_

#include <string>

#include "base/files/file_path.h"
#include "base/types/expected.h"
#include "dbus/object_proxy.h"
#include "dbus/shadercached/dbus-constants.h"
#include "shadercached/proto_bindings/shadercached.pb.h"

#include "vm_tools/concierge/vm_util.h"

namespace vm_tools::concierge {

// Creates the shader-cache-specific shared data parameter for crosvm.
SharedDataParam CreateShaderSharedDataParam(base::FilePath data_dir);

base::expected<shadercached::PrepareShaderCacheResponse, std::string>
PrepareShaderCache(const std::string& owner_id,
                   const std::string& vm_name,
                   scoped_refptr<dbus::Bus> bus_,
                   dbus::ObjectProxy* shadercached_proxy_);

std::string PurgeShaderCache(const std::string& owner_id,
                             const std::string& vm_name,
                             scoped_refptr<dbus::Bus> bus_,
                             dbus::ObjectProxy* shadercached_proxy_);

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_SHADERCACHED_HELPER_H_
