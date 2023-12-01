// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUSEBOX_BUILT_IN_H_
#define FUSEBOX_BUILT_IN_H_

// This file collects functions related to the built_in subdir.

#include <memory>
#include <string>

#include <dbus/object_proxy.h>

#include "fusebox/fuse_path_inodes.h"
#include "fusebox/fuse_request.h"

namespace fusebox {

void BuiltInEnsureNodes(InodeTable& itab);

void BuiltInGetStat(ino_t ino, struct stat* stat);

void BuiltInLookup(std::unique_ptr<EntryRequest> request,
                   const std::string& name);

void BuiltInRead(scoped_refptr<dbus::ObjectProxy> dbus_proxy,
                 std::unique_ptr<BufferRequest> request,
                 ino_t ino,
                 size_t size,
                 off_t off);

void BuiltInReadDir(off_t off, std::unique_ptr<DirEntryRequest> request);

}  // namespace fusebox

#endif  // FUSEBOX_BUILT_IN_H_
