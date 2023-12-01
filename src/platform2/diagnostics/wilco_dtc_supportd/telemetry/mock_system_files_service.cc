// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/mock_system_files_service.h"

#include <utility>

namespace diagnostics {
namespace wilco {

// static
SystemFilesService::FileDump MockSystemFilesService::CopyFileDump(
    const FileDump& file_dump) {
  FileDump copy_file_dump;
  copy_file_dump.path = file_dump.path;
  copy_file_dump.canonical_path = file_dump.canonical_path;
  copy_file_dump.contents = file_dump.contents;
  return copy_file_dump;
}

// static
SystemFilesService::FileDumps MockSystemFilesService::CopyFileDumps(
    const FileDumps& file_dumps) {
  FileDumps copy_file_dumps;
  for (const auto& file_dump : file_dumps) {
    auto copy_file_dump = std::make_unique<FileDump>();
    copy_file_dump->path = file_dump->path;
    copy_file_dump->canonical_path = file_dump->canonical_path;
    copy_file_dump->contents = file_dump->contents;
    copy_file_dumps.push_back(std::move(copy_file_dump));
  }
  return copy_file_dumps;
}

MockSystemFilesService::MockSystemFilesService() = default;

MockSystemFilesService::~MockSystemFilesService() = default;

}  // namespace wilco
}  // namespace diagnostics
