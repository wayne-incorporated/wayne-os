// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "virtual_file_provider/size_map.h"

namespace virtual_file_provider {

SizeMap::SizeMap() = default;

SizeMap::~SizeMap() = default;

void SizeMap::SetSize(const std::string& id, int64_t size) {
  base::AutoLock lock(id_to_size_lock_);
  id_to_size_[id] = size;
}

int64_t SizeMap::GetSize(const std::string& id) {
  base::AutoLock lock(id_to_size_lock_);
  auto it = id_to_size_.find(id);
  return it == id_to_size_.end() ? -1 : it->second;
}

bool SizeMap::Erase(const std::string& id) {
  base::AutoLock lock(id_to_size_lock_);
  return id_to_size_.erase(id) != 0;
}

}  // namespace virtual_file_provider
