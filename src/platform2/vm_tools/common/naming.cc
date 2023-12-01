// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/common/naming.h"

#include <base/base64url.h>

namespace vm_tools {

std::string GetEncodedName(const std::string& base_name) {
  std::string encoded;
  // Padding is unnecessary you say? And you'd be right, but unfortunately
  // certain important files were created with padding and we can't now go back
  // and remove it.
  base::Base64UrlEncode(base_name, base::Base64UrlEncodePolicy::INCLUDE_PADDING,
                        &encoded);
  return encoded;
}

std::string GetDecodedName(const std::string& encoded_name) {
  std::string decoded;
  if (!base::Base64UrlDecode(
          encoded_name, base::Base64UrlDecodePolicy::IGNORE_PADDING, &decoded))
    return "";
  return decoded;
}

}  // namespace vm_tools
