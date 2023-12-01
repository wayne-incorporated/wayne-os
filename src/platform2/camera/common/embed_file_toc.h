/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_EMBED_FILE_TOC_H_
#define CAMERA_COMMON_EMBED_FILE_TOC_H_

#include <map>
#include <string>

#include <base/containers/span.h>

#include "cros-camera/export.h"

namespace cros {

// A class the stores the entry metadata for a embedded file.
class CROS_CAMERA_EXPORT EmbeddedFileEntry {
 public:
  EmbeddedFileEntry(const char* content, size_t length);
  ~EmbeddedFileEntry() = default;

  base::span<const char> content() const { return {content_, length_}; }

 private:
  const char* content_;
  const size_t length_;
};

// A class that provides a table of contents for a set of embedded files.
class CROS_CAMERA_EXPORT EmbeddedFileToc {
 public:
  explicit EmbeddedFileToc(std::map<std::string, EmbeddedFileEntry> toc);
  ~EmbeddedFileToc() = default;

  base::span<const char> Get(const std::string& key) const;

 private:
  std::map<std::string, EmbeddedFileEntry> toc_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_EMBED_FILE_TOC_H_
