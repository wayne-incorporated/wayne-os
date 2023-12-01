// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/rar_mounter.h"

#include <algorithm>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/metrics.h"
#include "cros-disks/platform.h"

namespace cros_disks {
namespace {
const char kExtension[] = ".rar";
}  // namespace

RarMounter::RarMounter(const Platform* platform,
                       brillo::ProcessReaper* process_reaper,
                       Metrics* metrics,
                       std::unique_ptr<SandboxedProcessFactory> sandbox_factory)
    : ArchiveMounter(platform,
                     process_reaper,
                     "rar",
                     "rar",
                     metrics,
                     "Rar2fs",
                     {12,   // ERAR_BAD_DATA
                      22,   // ERAR_MISSING_PASSWORD
                      24},  // ERAR_BAD_PASSWORD
                     std::move(sandbox_factory),
                     {"-o", "locale=en_US.UTF8"}) {}

RarMounter::~RarMounter() = default;

bool RarMounter::Increment(const std::string::iterator begin,
                           std::string::iterator end) {
  while (true) {
    if (begin == end) {
      // Overflow.
      return false;
    }

    char& c = *--end;

    if (c == '9') {
      // Roll 9 to 0.
      c = '0';
    } else if (c == 'z') {
      // Roll z to a.
      c = 'a';
    } else if (c == 'Z') {
      // Roll Z to A.
      c = 'A';
    } else {
      // Increment any other character and done.
      ++c;
      return true;
    }
  }
}

RarMounter::IndexRange RarMounter::ParseDigits(base::StringPiece path) {
  const base::StringPiece extension = kExtension;

  if (!base::EndsWith(path, extension, base::CompareCase::INSENSITIVE_ASCII))
    return {};

  path.remove_suffix(extension.size());
  const size_t end = path.size();

  while (!path.empty() && base::IsAsciiDigit(path.back()))
    path.remove_suffix(1);

  return {path.size(), end};
}

void RarMounter::AddPathsWithOldNamingScheme(
    std::vector<std::string>* const bind_paths,
    const base::StringPiece original_path) const {
  DCHECK(bind_paths);

  // Is the extension right?
  if (!base::EndsWith(original_path, kExtension,
                      base::CompareCase::INSENSITIVE_ASCII))
    return;

  // Prepare candidate path.
  std::string candidate_path(original_path);
  const std::string::iterator end = candidate_path.end();

  // Set the last 2 characters to '0', so that extension '.rar' becomes '.r00'
  // and extension '.RAR' becomes '.R00'.
  std::fill(end - 2, end, '0');

  // Is there at least the first supplementary file of the multipart archive?
  if (!platform()->PathExists(candidate_path))
    return;

  bind_paths->push_back(candidate_path);

  // Iterate by incrementing the last 3 characters of the extension:
  // '.r00' -> '.r01' -> ... -> '.r99' -> '.s00' -> ... -> '.z99'
  // or
  // '.R00' -> '.R01' -> ... -> '.R99' -> '.S00' -> ... -> '.Z99'
  while (Increment(end - 3, end) && platform()->PathExists(candidate_path))
    bind_paths->push_back(candidate_path);
}

void RarMounter::AddPathsWithNewNamingScheme(
    std::vector<std::string>* const bind_paths,
    const base::StringPiece original_path,
    const IndexRange& digits) const {
  DCHECK(bind_paths);
  DCHECK_LT(digits.begin, digits.end);
  DCHECK_LE(digits.end, original_path.size());

  // Prepare candidate path.
  std::string candidate_path(original_path);

  // [begin, end) is the digit range to increment.
  const std::string::iterator begin = candidate_path.begin() + digits.begin;
  const std::string::iterator end = candidate_path.begin() + digits.end;

  // Fill the digit range with zeros.
  std::fill(begin, end, '0');

  // Find all the files making the multipart archive.
  while (Increment(begin, end) && platform()->PathExists(candidate_path)) {
    if (candidate_path != original_path)
      bind_paths->push_back(candidate_path);
  }
}

std::vector<std::string> RarMounter::GetBindPaths(
    const base::StringPiece original_path) const {
  std::vector<std::string> bind_paths = {std::string(original_path)};

  // Delimit the digit range assuming original_path uses the new naming scheme.
  const IndexRange digits = ParseDigits(original_path);
  if (digits.empty()) {
    // Use the old naming scheme.
    AddPathsWithOldNamingScheme(&bind_paths, original_path);
  } else {
    // Use the new naming scheme.
    AddPathsWithNewNamingScheme(&bind_paths, original_path, digits);
  }

  return bind_paths;
}

}  // namespace cros_disks
