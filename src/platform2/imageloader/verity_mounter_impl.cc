// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/verity_mounter_impl.h"

#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace imageloader {

bool MapperParametersToLoop(const std::string& verity_mount_parameters,
                            int32_t* loop) {
  // Parameters should be of the form:
  // "0 7:6 7:6 4096 4096 3089 3089 sha256 eef4aa5dc50d181b7f6..."
  auto tokens = base::SplitString(verity_mount_parameters, " ",
                                  base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (tokens.size() < 2) {
    LOG(ERROR) << "Not enough parameters";
    return false;
  }

  tokens = base::SplitString(tokens[1], ":", base::TRIM_WHITESPACE,
                             base::SPLIT_WANT_ALL);

  if (tokens.size() < 2) {
    LOG(ERROR) << "Unexpected token format";
    return false;
  }

  return base::StringToInt(tokens[1], loop);
}

bool IsAncestor(const base::FilePath& ancenstor,
                const base::FilePath& descendant) {
  std::vector<std::string> ancenstor_components = ancenstor.GetComponents();
  std::vector<std::string> descendant_components = descendant.GetComponents();
  if (descendant_components.size() <= ancenstor_components.size()) {
    return false;
  }
  return std::mismatch(ancenstor_components.begin(), ancenstor_components.end(),
                       descendant_components.begin())
             .first == ancenstor_components.end();
}

}  // namespace imageloader
