// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_PLATFORM_HELPER_H_
#define AUTHPOLICY_PLATFORM_HELPER_H_

#include <string>

#include <base/files/scoped_file.h>

namespace base {
class FilePath;
}

namespace authpolicy {

// Reads the whole contents of the file descriptor |fd| into the string |out|.
// If fd is a blocking pipe this call will block until the pipe is closed.
// Returns true iff the whole pipe was successfully read and the pipe was
// smaller than some limit (see code).
bool ReadPipeToString(int fd, std::string* out);

// Creates a non-blocking pipe and writes the given string to it. |str| must be
// small enough to fit into the pipe buffer. Returns base::ScopedFD() on error.
base::ScopedFD WriteStringToPipe(const std::string& str);

// Creates a non-blocking pipe and writes the given string and the contents of
// the given pipe to it. The pipe buffer must be big enough to hold the data.
// Returns base::ScopedFD() on error.
base::ScopedFD WriteStringAndPipeToPipe(const std::string& str, int fd);

// Reads the file at |path| into a pipe and returns the corresponding file
// descriptor. The descriptor is invalid in case reading the file failed or it
// could not be copied in one go (e.g. file too big). Only works for files
// smaller than PIPE_BUF.
base::ScopedFD ReadFileToPipe(const base::FilePath& path);

// Performs concurrent IO for three different pipes:
// - Reads data from |stdout_fd| into |stdout|.
// - Reads data from |stderr_fd| into |stderr|.
// - Writes data from |input_str| into |stdin_fd|.
//   If |input_fd| is not -1, splices the whole pipe into |stdin_fd| first.
// Returns false on error. May block if any of the pipes is a blocking pipe.
bool PerformPipeIo(int stdin_fd,
                   int stdout_fd,
                   int stderr_fd,
                   int input_fd,
                   const std::string& input_str,
                   std::string* stdout,
                   std::string* stderr);

// Duplicating pipe content from |src_fd|. Returns valid base::ScopedFD on
// success. Should never block.
base::ScopedFD DuplicatePipe(int src_fd);

// Gets the current effective user id.
uid_t GetEffectiveUserId();

// Sets the given UID as saved UID and drops caps. This way, the UID can be
// switched to the saved UID even without keeping caps around. That's more
// secure.
bool SetSavedUserAndDropCaps(uid_t saved_uid);

// Helper class that swaps the real/effective UID with the saved UID in its
// scope. The real and effective UIDs have to match, so that the real/effective
// UID can be restored from the saved UID. Dies on error.
// This is usually used to run stuff as authpolicyd-exec user.
class ScopedSwitchToSavedUid {
 public:
  ScopedSwitchToSavedUid();
  ScopedSwitchToSavedUid(const ScopedSwitchToSavedUid&) = delete;
  ScopedSwitchToSavedUid& operator=(const ScopedSwitchToSavedUid&) = delete;

  ~ScopedSwitchToSavedUid();

 private:
  uid_t real_and_effective_uid_ = -1;
  uid_t saved_uid_ = -1;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_PLATFORM_HELPER_H_
