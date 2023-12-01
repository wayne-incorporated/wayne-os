// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/disk_cache_blob.h"

#include <fcntl.h>

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/logging.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/database.pb.h"

namespace vtpm {

DiskCacheBlob::DiskCacheBlob(const base::FilePath& path) : path_(path) {}

trunks::TPM_RC DiskCacheBlob::Get(std::string& blob) {
  if (!base::PathExists(path_)) {
    return trunks::TPM_RC_SUCCESS;
  }
  std::string buffer;
  if (!base::ReadFileToString(path_, &buffer)) {
    return trunks::TPM_RC_FAILURE;
  }
  BlobData data;
  if (!data.ParseFromString(buffer)) {
    return trunks::TPM_RC_FAILURE;
  }
  blob = data.blob();
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC DiskCacheBlob::Write(const std::string& blob) {
  BlobData data;
  data.set_blob(blob);
  std::string buffer;
  if (!data.SerializeToString(&buffer)) {
    return trunks::TPM_RC_FAILURE;
  }

  // Note that it is assumed that the directory of `path_` exists.

  if (!base::ImportantFileWriter::WriteFileAtomically(path_, buffer)) {
    LOG(ERROR) << __func__ << "Failed to write file: " << path_.value();
    return trunks::TPM_RC_FAILURE;
  }
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
