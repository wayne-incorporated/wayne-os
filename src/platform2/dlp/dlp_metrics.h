// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLP_DLP_METRICS_H_
#define DLP_DLP_METRICS_H_

#include <memory>
#include <metrics/metrics_library.h>
#include <string>

namespace dlp {

constexpr char kDlpFanotifyDeleteEventSupport[] =
    "Enterprise.Dlp.FanotifyDeleteEventSupport";
constexpr char kDlpFanotifyMarkFilesystemSupport[] =
    "Enterprise.Dlp.FanotifyMarkFilesystemSupport";

constexpr char kDlpInitErrorHistogram[] = "Enterprise.Dlp.Errors.DaemonInit";
constexpr char kDlpFanotifyErrorHistogram[] = "Enterprise.Dlp.Errors.Fanotify";
constexpr char kDlpFileDatabaseErrorHistogram[] =
    "Enterprise.Dlp.Errors.FileDatabase";
constexpr char kDlpAdaptorErrorHistogram[] = "Enterprise.Dlp.Errors.Adaptor";

// Type of errors triggered during the initialization of the DLP daemon.
enum class InitError {
  kUnknownError = 0,
  // Error while retrieving the primary username.
  kPrimaryUsernameRetrievalError = 1,
  // For SendEnumToUMA() usage.
  kMaxValue = kPrimaryUsernameRetrievalError
};

// Type of errors triggered by fanotify usage in the DLP daemon.
enum class FanotifyError {
  kUnknownError = 0,
  // Error when executing fanotify_mark.
  kMarkError = 1,
  // Error when executing select in FanotifyReaderThread.
  kSelectError = 2,
  // Error when executing ioctl in FanotifyReaderThread.
  kIoctlError = 3,
  // Error when executing fd in FanotifyReaderThread.
  kFdError = 4,
  // Error triggered when there is a mismatch of fanotify metadata version.
  kMetadataMismatchError = 5,
  // Error when executing fstat in FanotifyReaderThread.
  kFstatError = 6,
  // Error triggered when receiving an invalid file descriptor.
  kInvalidFileDescriptorError = 7,
  // Error triggered when receiving an unexpected file handle type.
  kUnexpectedFileHandleTypeError = 8,
  // Error triggered when receiving an unexpected event info type.
  kUnexpectedEventInfoTypeError = 9,
  // Error during initialization.
  kInitError = 10,
  // For SendEnumToUMA() usage.
  kMaxValue = kInitError,
};

// Type of errors triggered by the DLP database.
enum class DatabaseError {
  kUnknownError = 0,
  // Error when connecting to the database.
  kConnectionError = 1,
  // Error when creating a database table.
  kCreateTableError = 2,
  // Error when inserting an entry into a database table.
  kInsertIntoTableError = 3,
  // Error when querying the database.
  kQueryError = 4,
  // Error when deleting database entries.
  kDeleteError = 5,
  // Error triggered when a query returns multiple database entries for the same
  // inode.
  kMultipleEntriesForInode = 6,
  // Error while creating the database directory.
  kCreateDirError = 7,
  // Error while setting database ownership.
  kSetOwnershipError = 8,
  // For SendEnumToUMA() usage.
  kMaxValue = kSetOwnershipError,
};

// Type of errors triggered by the DLP adaptor.
enum class AdaptorError {
  kUnknownError = 0,
  // Error triggered when parsing a invalid proto.
  kInvalidProtoError = 1,
  // Error triggered when the file database is unexpectedly not ready.
  kDatabaseNotReadyError = 2,
  // Error while connecting to the file database.
  kDatabaseConnectionError = 3,
  // Error while getting a file inode.
  kInodeRetrievalError = 4,
  // Error while creating a pipe.
  kCreatePipeError = 5,
  // Error triggered when it is not possible to check file restrictions.
  kRestrictionDetectionError = 6,
  // Error while adding a file.
  kAddFileError = 7,
  // Error while executing dup on a FD.
  kFileDescriptorDupError = 8,
  // Error while executing close on a FD.
  kFileDescriptorCloseError = 9,
  // Files were not added because DB failed to be created on time.
  kAddFileNotCompleteBeforeDestruction = 10,
  // For SendEnumToUMA() usage.
  kMaxValue = kAddFileNotCompleteBeforeDestruction,
};

// Sends UMAs related to the DLP daemon.
class DlpMetrics {
 public:
  DlpMetrics();
  ~DlpMetrics();

  // Send a boolean to UMA.
  void SendBooleanHistogram(const std::string& name, bool value) const;

  // Records whether there's an error happening during the daemon
  // initialization.
  void SendInitError(InitError error) const;

  // Records whether there's an error happening when using fanotify.
  void SendFanotifyError(FanotifyError error) const;

  // Records whether an error occurs while executing database procedures.
  void SendDatabaseError(DatabaseError error) const;

  // Records whether an error occurs while executing adaptor procedures.
  void SendAdaptorError(AdaptorError error) const;

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
};

}  // namespace dlp

#endif  // DLP_DLP_METRICS_H_
