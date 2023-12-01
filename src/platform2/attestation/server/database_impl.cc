// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/database_impl.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <brillo/secure_blob.h>

using base::FilePath;

namespace {

const char kDatabasePath[] =
    "/mnt/stateful_partition/unencrypted/preserve/attestation.epb";
const mode_t kDatabasePermissions = 0600;

}  // namespace

namespace attestation {

DatabaseImpl::DatabaseImpl(CryptoUtility* crypto,
                           const hwsec::AttestationFrontend* hwsec)
    : io_(this), crypto_(crypto), hwsec_(hwsec) {}

DatabaseImpl::~DatabaseImpl() {
  brillo::SecureClearContainer(database_key_);
}

bool DatabaseImpl::Initialize() {
  if (!Reload()) {
    LOG(WARNING) << "Creating new attestation database.";
    return false;
  }
  return true;
}

const AttestationDatabase& DatabaseImpl::GetProtobuf() const {
  return protobuf_;
}

AttestationDatabase* DatabaseImpl::GetMutableProtobuf() {
  return &protobuf_;
}

bool DatabaseImpl::SaveChanges() {
  std::string buffer;
  if (!EncryptProtobuf(&buffer)) {
    return false;
  }
  return io_->Write(buffer);
}

bool DatabaseImpl::Reload() {
  LOG(INFO) << "Loading attestation database.";
  std::string buffer;
  if (!io_->Read(&buffer)) {
    return false;
  }
  return DecryptProtobuf(buffer);
}

bool DatabaseImpl::Read(std::string* data) {
  const int kMask = base::FILE_PERMISSION_OTHERS_MASK;
  FilePath path(kDatabasePath);
  int permissions = 0;
  if (base::GetPosixFilePermissions(path, &permissions) &&
      (permissions & kMask) != 0) {
    LOG(WARNING) << "Attempting to fix permissions on attestation database.";
    base::SetPosixFilePermissions(path, permissions & ~kMask);
  }
  if (!base::ReadFileToString(path, data)) {
    PLOG(ERROR) << "Failed to read attestation database";
    return false;
  }
  return true;
}

bool DatabaseImpl::Write(const std::string& data) {
  FilePath file_path(kDatabasePath);
  if (!base::CreateDirectory(file_path.DirName())) {
    LOG(ERROR) << "Cannot create directory: " << file_path.DirName().value();
    return false;
  }
  if (!base::ImportantFileWriter::WriteFileAtomically(file_path, data)) {
    LOG(ERROR) << "Failed to write file: " << file_path.value();
    return false;
  }
  if (!base::SetPosixFilePermissions(file_path, kDatabasePermissions)) {
    LOG(ERROR) << "Failed to set permissions for file: " << file_path.value();
    return false;
  }
  // Sync the parent directory.
  std::string dir_name = file_path.DirName().value();
  int dir_fd = HANDLE_EINTR(open(dir_name.c_str(), O_RDONLY | O_DIRECTORY));
  if (dir_fd < 0) {
    PLOG(WARNING) << "Could not open " << dir_name << " for syncing";
    return false;
  }
  // POSIX specifies EINTR as a possible return value of fsync().
  int result = HANDLE_EINTR(fsync(dir_fd));
  if (result < 0) {
    PLOG(WARNING) << "Failed to sync " << dir_name;
    close(dir_fd);
    return false;
  }
  // close() may not be retried on error.
  result = IGNORE_EINTR(close(dir_fd));
  if (result < 0) {
    PLOG(WARNING) << "Failed to close after sync " << dir_name;
    return false;
  }
  return true;
}

bool DatabaseImpl::EncryptProtobuf(std::string* encrypted_output) {
  std::string serial_proto;
  if (!protobuf_.SerializeToString(&serial_proto)) {
    LOG(ERROR) << "Failed to serialize db.";
    return false;
  }
  CHECK_EQ(database_key_.empty(), sealed_database_key_.empty())
      << "Raw and sealed keys should be present in pair.";
  if (database_key_.empty()) {
    if (auto result = hwsec_->GetCurrentBootMode(); !result.ok()) {
      LOG(ERROR) << __func__
                 << "Invalid boot mode, aborting: " << result.status();
      metrics_.ReportAttestationOpsStatus(
          kAttestationEncryptDatabase, AttestationOpsStatus::kInvalidPcr0Value);
      return false;
    }

    if (!crypto_->CreateSealedKey(&database_key_, &sealed_database_key_)) {
      LOG(ERROR) << "Failed to generate database key.";
      metrics_.ReportAttestationOpsStatus(kAttestationEncryptDatabase,
                                          AttestationOpsStatus::kFailure);
      return false;
    }
  }
  if (!crypto_->EncryptData(serial_proto, database_key_, sealed_database_key_,
                            encrypted_output)) {
    LOG(ERROR) << "Attestation: Failed to encrypt database.";
    metrics_.ReportAttestationOpsStatus(kAttestationEncryptDatabase,
                                        AttestationOpsStatus::kFailure);
    return false;
  }
  metrics_.ReportAttestationOpsStatus(kAttestationEncryptDatabase,
                                      AttestationOpsStatus::kSuccess);
  return true;
}

bool DatabaseImpl::DecryptProtobuf(const std::string& encrypted_input) {
  if (auto result = hwsec_->GetCurrentBootMode(); !result.ok()) {
    LOG(ERROR) << __func__ << "Invalid boot mode: " << result.status();
    metrics_.ReportAttestationOpsStatus(
        kAttestationDecryptDatabase, AttestationOpsStatus::kInvalidPcr0Value);
    return false;
  }

  if (!crypto_->UnsealKey(encrypted_input, &database_key_,
                          &sealed_database_key_)) {
    LOG(ERROR) << "Attestation: Could not unseal decryption key.";
    metrics_.ReportAttestationOpsStatus(kAttestationDecryptDatabase,
                                        AttestationOpsStatus::kFailure);
    return false;
  }
  std::string serial_proto;
  if (!crypto_->DecryptData(encrypted_input, database_key_, &serial_proto)) {
    LOG(ERROR) << "Attestation: Failed to decrypt database.";
    metrics_.ReportAttestationOpsStatus(kAttestationDecryptDatabase,
                                        AttestationOpsStatus::kFailure);
    return false;
  }
  if (!protobuf_.ParseFromString(serial_proto)) {
    // Previously the DB was encrypted with CryptoLib::AesEncrypt which appends
    // a SHA-1.  This can be safely ignored.
    const size_t kLegacyJunkSize = 20;
    if (serial_proto.size() < kLegacyJunkSize ||
        !protobuf_.ParseFromArray(serial_proto.data(),
                                  serial_proto.length() - kLegacyJunkSize)) {
      LOG(ERROR) << "Failed to parse database.";
      metrics_.ReportAttestationOpsStatus(kAttestationDecryptDatabase,
                                          AttestationOpsStatus::kFailure);
      return false;
    }
  }
  metrics_.ReportAttestationOpsStatus(kAttestationDecryptDatabase,
                                      AttestationOpsStatus::kSuccess);
  return true;
}

}  // namespace attestation
