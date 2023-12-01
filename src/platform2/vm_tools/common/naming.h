// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_COMMON_NAMING_H_
#define VM_TOOLS_COMMON_NAMING_H_

#include <ostream>
#include <string>
#include <utility>

namespace vm_tools {

// Gets the "encoded" version of |base_name|, which is a filename-safe 1:1
// mapping of it. This is the RFC-4648 base64 URL encoding with padding.
std::string GetEncodedName(const std::string& base_name);

// Reverse of GetEncodedName. Returns the empty string if the decoding fails.
std::string GetDecodedName(const std::string& encoded_name);

}  // namespace vm_tools

#endif  // VM_TOOLS_COMMON_NAMING_H_
