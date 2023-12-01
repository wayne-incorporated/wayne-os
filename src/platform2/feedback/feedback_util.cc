// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include <brillo/process/process.h>

namespace {

static const char kZipProcess[] = "/usr/bin/bzip2";

}  // namespace

namespace feedback_util {

// Compresses |data| into an archive, and reads it back into |compressed_logs|.
// |filename| is the name of the file to appear in the archive (if supported
// by type).
bool ZipString(const base::FilePath& filename,
               const std::string& data,
               std::string* compressed_logs) {
  base::FilePath temp_path;
  base::FilePath zip_file;

  if (!base::PathExists(base::FilePath(kZipProcess)))
    return false;

  // Create a temporary directory, put the logs into a file in it. Create
  // another temporary file to receive the zip file in.
  if (!base::CreateNewTempDirectory(std::string(), &temp_path))
    return false;
  if (base::WriteFile(temp_path.Append(filename), data.c_str(), data.size()) ==
      -1)
    return false;

  brillo::ProcessImpl zipprocess;
  zipprocess.AddArg(kZipProcess);
  zipprocess.AddArg(filename.value());
  zipprocess.RedirectOutput(temp_path.value());
  bool succeeded = base::CreateTemporaryFile(&zip_file) && !zipprocess.Run() &&
                   base::ReadFileToString(zip_file, compressed_logs);

  base::DeletePathRecursively(temp_path);
  base::DeleteFile(zip_file);

  return succeeded;
}

}  // namespace feedback_util
