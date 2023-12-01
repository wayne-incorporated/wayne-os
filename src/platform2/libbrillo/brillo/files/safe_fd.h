// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This provides an API for performing typical filesystem related tasks while
// guaranteeing certain security properties are maintained. Specifically, checks
// are performed to disallow symbolic links, and exotic file objects. The goal
// behind these checks is to thwart attacks that rely on confusing system
// services to perform unintended file operations like ownership changes or
// copy-as-root attack primitives. To accomplish this these operations are
// written to avoid susceptibility to TOCTOU (time-of-check-time-of-use)
// attacks.

// To use this API start with the root path and work from there. For example:
// SafeFD fd(SafeDirFD::Root().MakeFile(PATH).first);
// if (!fd.is_valid()) {
//   LOG(ERROR) << "Failed to open " << PATH;
//   return false;
// }
// if (fd.WriteString(CONTENTS) != SafeFD::kNoError) {
//   LOG(ERROR) << "Failed to write to " << PATH;
//   return false;
// }
// auto read_result = fd.ReadString();
// if (!read_result.second != SafeFD::kNoError) {
//   LOG(ERROR) << "Failed to read from " << PATH;
//   return false;
// }

#ifndef LIBBRILLO_BRILLO_FILES_SAFE_FD_H_
#define LIBBRILLO_BRILLO_FILES_SAFE_FD_H_

#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/synchronization/lock.h>
#include <brillo/brillo_export.h>
#include <gtest/gtest_prod.h>

namespace brillo {

class SafeFDTest;

class SafeFD {
 public:
  SafeFD(const SafeFD&) = delete;
  SafeFD& operator=(const SafeFD&) = delete;
  enum class Error {
    kNoError = 0,
    kBadArgument,
    kNotInitialized,  // Invalid operation on a SafeFD that was not initialized.
    kIOError,         // Check errno for specific cause.
    kDoesNotExist,    // The specified path does not exist.
    kSymlinkDetected,
    kBoundaryDetected,  // Detected a file system boundary during recursion.
    kWrongType,         // (e.g. got a directory and expected a file)
    kWrongUID,
    kWrongGID,
    kWrongPermissions,
    kExceededMaximum,  // The maximum allowed read size was reached.
  };

  // Returns true if |err| denotes a failed operation.
  BRILLO_EXPORT static bool IsError(SafeFD::Error err);

  typedef std::pair<SafeFD, Error> SafeFDResult;

  // 100 MiB
  BRILLO_EXPORT static constexpr size_t kDefaultMaxRead = 100 << 20;
  // One page is usually 4 KiB. This is the typical file size limit for
  // psuedo-fs such as /proc or /sys.
  BRILLO_EXPORT static constexpr size_t kDefaultPageSize = 4 << 10;
  BRILLO_EXPORT static constexpr size_t kDefaultMaxPathDepth = 256;
  // User read and write only.
  BRILLO_EXPORT static constexpr size_t kDefaultFilePermissions = 0640;
  // User read, write, and execute. Group read and execute.
  BRILLO_EXPORT static constexpr size_t kDefaultDirPermissions = 0750;

  // Get a SafeFD to the root path.
  [[nodiscard]] BRILLO_EXPORT static SafeFDResult Root();
  BRILLO_EXPORT static void SetRootPathForTesting(const char* new_root_path);

  // Constructs an invalid fd;
  BRILLO_EXPORT SafeFD() = default;

  // Move-based constructor and assignment.
  BRILLO_EXPORT SafeFD(SafeFD&&) = default;
  BRILLO_EXPORT SafeFD& operator=(SafeFD&&) = default;

  // Return the fd number.
  [[nodiscard]] BRILLO_EXPORT int get() const;

  // Check the validity of the file descriptor.
  [[nodiscard]] BRILLO_EXPORT bool is_valid() const;

  // Close the scoped file if one was open.
  BRILLO_EXPORT void reset();

  // Wrap |fd| with a SafeFD which will close the fd when this goes out of
  // scope. This closes the original fd if one was open.
  // This is named "Unsafe" because the recommended way to get a SafeFD
  // instance is opening one from SafeFD::Root().
  BRILLO_EXPORT void UnsafeReset(int fd);

  // Writes |size| bytes from |data| replacing the contents of a file and
  // returns kNoError on success. Note the file will be truncated to the
  // size of the content.
  //
  // Intended use cases:
  // * Making a file that contains exactly |data|.
  //
  // Parameters
  //  data - The buffer to write to the file.
  //  size - The number of bytes to write.
  [[nodiscard]] BRILLO_EXPORT Error Replace(const char* data, size_t size);

  // Writes |size| bytes from |data| to the file and returns kNoError on
  // success. Note the file will **NOT** be truncated to the size of the
  // content, and the data will be written to the current file cursor position.
  //
  // Intended use cases:
  // * Writing to FIFOs, sockets, etc. where seek or truncate are not
  //   available.
  // * To append to a file (e.g. opened with O_APPEND or
  //   lseek(fd.get(), 0, SEEK_END).
  //
  // Parameters
  //  data - The buffer to write to the file.
  //  size - The number of bytes to write.
  [[nodiscard]] BRILLO_EXPORT Error Write(const char* data, size_t size);

  // Read the contents of the file and return it as a string.
  //
  // Parameters
  //  size - The max number of bytes to read.
  [[nodiscard]] BRILLO_EXPORT std::pair<std::vector<char>, Error> ReadContents(
      size_t max_size = kDefaultMaxRead);

  // Reads exactly |size| bytes into |data|.
  //
  // Parameters
  //  data - The buffer to read the file into.
  //  size - The number of bytes to read.
  [[nodiscard]] BRILLO_EXPORT Error Read(char* data, size_t size);

  // Reads at most |max_size| bytes into |data|.
  //
  // Parameters
  //  data - The buffer to read the file into.
  //  max_size - The maximum number of bytes to read (typically, the size of
  //    the buffer).
  [[nodiscard]] BRILLO_EXPORT std::pair<size_t, Error> ReadUntilEnd(
      char* data, size_t max_size);

  // Copy the contents of this file to |destination|.
  //
  // Parameters
  //  destination - An open safe fd that will be written to with the contents of
  //    |this|.
  //  size - The max number of bytes to copy. If this amount is reached,
  //    Error::kExceededMaximum is returned.
  [[nodiscard]] BRILLO_EXPORT Error
  CopyContentsTo(SafeFD* destination, size_t max_size = kDefaultMaxRead);

  // Open an existing file relative to this directory.
  //
  // Parameters
  //  path - The path to open relative to the current directory.
  [[nodiscard]] BRILLO_EXPORT SafeFDResult
  OpenExistingFile(const base::FilePath& path, int flags = O_RDWR | O_CLOEXEC);

  // Open an existing directory relative to this directory.
  //
  // Parameters
  //  path - The path to open relative to the current directory.
  [[nodiscard]] BRILLO_EXPORT SafeFDResult
  OpenExistingDir(const base::FilePath& path, int flags = O_RDONLY | O_CLOEXEC);

  // Open a file relative to this directory creating the parent directories and
  // file if they don't already exist.
  [[nodiscard]] BRILLO_EXPORT SafeFDResult
  MakeFile(const base::FilePath& path,
           mode_t permissions = kDefaultFilePermissions,
           uid_t uid = getuid(),
           gid_t gid = getgid(),
           int flags = O_RDWR | O_CLOEXEC);

  // Create the directories in the relative path with the given ownership and
  // permissions and return a file descriptor to the result.
  [[nodiscard]] BRILLO_EXPORT SafeFDResult
  MakeDir(const base::FilePath& path,
          mode_t permissions = kDefaultDirPermissions,
          uid_t uid = getuid(),
          gid_t gid = getgid(),
          int flags = O_RDONLY | O_CLOEXEC);

  // Hard link |fd| in the directory represented by |this| with the specified
  // name |filename|. This requires CAP_DAC_READ_SEARCH.
  //
  // Parameters
  //  data - The buffer to write to the file.
  //  size - The number of bytes to write.
  [[nodiscard]] BRILLO_EXPORT Error Link(const SafeFD& source_dir,
                                         const std::string& source_name,
                                         const std::string& destination_name);

  // Deletes the child path named |name|.
  //
  // Parameters
  //  name - the name of the filesystem object to delete.
  [[nodiscard]] BRILLO_EXPORT Error Unlink(const std::string& name);

  // Deletes a child directory. It will return kBoundaryDetected if a file
  // system boundary is reached during recursion.
  //
  // Parameters
  //  name - the name of the directory to delete.
  //  recursive - if true also unlink child paths.
  //  max_depth - limit on recursion depth to prevent fd exhaustion and stack
  //    overflows.
  //  keep_going - in recursive case continue deleting even in the face of
  //    errors. If all entries cannot be deleted, the last error encountered
  //    during recursion is returned.
  [[nodiscard]] BRILLO_EXPORT Error
  Rmdir(const std::string& name,
        bool recursive = false,
        size_t max_depth = kDefaultMaxPathDepth,
        bool keep_going = true);

 private:
  FRIEND_TEST(SafeFDTest, CopyContentsTo_PseudoFsLargeFallbackSuccess);

  BRILLO_EXPORT static const char* RootPath;

  base::ScopedFD fd_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_FILES_SAFE_FD_H_
