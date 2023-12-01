/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/embed_file_toc.h"

#include <utility>

namespace cros {

EmbeddedFileEntry::EmbeddedFileEntry(const char* content, size_t length)
    : content_(content), length_(length) {}

EmbeddedFileToc::EmbeddedFileToc(std::map<std::string, EmbeddedFileEntry> toc)
    : toc_(std::move(toc)) {}

base::span<const char> EmbeddedFileToc::Get(const std::string& key) const {
  auto iter = toc_.find(key);
  if (iter == toc_.end()) {
    return {};
  }
  return iter->second.content();
}

}  // namespace cros
