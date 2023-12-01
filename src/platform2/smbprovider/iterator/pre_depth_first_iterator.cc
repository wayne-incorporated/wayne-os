// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/iterator/pre_depth_first_iterator.h"

#include "smbprovider/proto.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {

PreDepthFirstIterator::PreDepthFirstIterator(const std::string& dir_path,
                                             SambaInterface* samba_interface)
    : DepthFirstIterator(dir_path, samba_interface) {}

int32_t PreDepthFirstIterator::OnPush(const DirectoryEntry& entry) {
  SetCurrent(entry);
  return 0;
}

}  // namespace smbprovider
