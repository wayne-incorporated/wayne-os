// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_MIME_TYPES_PARSER_H_
#define VM_TOOLS_GARCON_MIME_TYPES_PARSER_H_

#include <map>
#include <string>
#include <vector>

namespace vm_tools {
namespace garcon {

using MimeTypeMap = std::map<std::string, std::string>;

// Parses a file at |file_name| which should be in the same format as the
// /usr/share/mime/mime.cache file on Linux.
// https://specifications.freedesktop.org/shared-mime-info-spec/shared-mime-info-spec-0.21.html#idm46070612075440
// |out_mime_types| will be populated with keys that are a file extension and a
// value that is a MIME type. Returns true if there was a valid list parsed
// from the file and false otherwise. Later values in the file will take
// precedence over prior ones.
bool ParseMimeTypes(const std::string& file_name, MimeTypeMap* out_mime_types);

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_MIME_TYPES_PARSER_H_
