// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/filesystem_label.h"

#include <cctype>
#include <cstring>

#include <base/logging.h>
#include <base/strings/string_util.h>

#include "cros-disks/quote.h"

namespace cros_disks {

namespace {

struct LabelParameters {
  const char* filesystem_type;
  const size_t max_label_length;
};

// Allowed non-alphanumeric characters in volume label for compatibility with
// DOS short filenames
// See https://en.wikipedia.org/wiki/8.3_filename#Directory_table for details
const char kAllowedCharacters[] = {' ', '!', '#', '$', '%', '&', '(', ')',
                                   '-', '@', '^', '_', '`', '{', '}', '~'};

// Supported file systems and their parameters
const LabelParameters kSupportedLabelParameters[] = {
    {"vfat", 11}, {"exfat", 15}, {"ntfs", 32}};

const LabelParameters* FindLabelParameters(const std::string& filesystem_type) {
  for (const auto& parameters : kSupportedLabelParameters) {
    if (filesystem_type == parameters.filesystem_type) {
      return &parameters;
    }
  }

  return nullptr;
}

}  // namespace

LabelError ValidateVolumeLabel(const std::string& volume_label,
                               const std::string& filesystem_type) {
  // Check if the file system is supported for renaming
  const LabelParameters* parameters = FindLabelParameters(filesystem_type);
  if (!parameters) {
    LOG(WARNING) << filesystem_type
                 << " filesystem is not supported for labelling";
    return LabelError::kUnsupportedFilesystem;
  }

  // Check if new volume label satisfies file system volume label conditions
  // Volume label length
  if (volume_label.size() > parameters->max_label_length) {
    LOG(WARNING) << "New volume label " << quote(volume_label)
                 << " exceeds the limit of " << parameters->max_label_length
                 << " characters for the filesystem "
                 << quote(parameters->filesystem_type);
    return LabelError::kLongName;
  }

  // Check if the new volume label contains only alphanumeric ASCII characters
  // or allowed non-alphanumeric characters
  for (char value : volume_label) {
    if (!base::IsAsciiAlpha(value) && !base::IsAsciiDigit(value) &&
        !std::memchr(kAllowedCharacters, value, sizeof(kAllowedCharacters))) {
      LOG(WARNING) << "New volume label " << quote(volume_label)
                   << " contains forbidden character '" << value << "'";
      return LabelError::kInvalidCharacter;
    }
  }

  return LabelError::kSuccess;
}

}  // namespace cros_disks
