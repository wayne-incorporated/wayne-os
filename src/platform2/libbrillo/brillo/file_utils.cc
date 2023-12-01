// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/file_utils.h"

#include <fcntl.h>
#include <unistd.h>

#include <iterator>
#include <limits>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

#include "brillo/files/file_util.h"

namespace brillo {

namespace {

// Log sync(), fsync(), etc. calls that take this many seconds or longer.
constexpr const base::TimeDelta kLongSync = base::Seconds(10);

enum {
  kPermissions600 = S_IRUSR | S_IWUSR,
  kPermissions777 = S_IRWXU | S_IRWXG | S_IRWXO,
  kPermissions755 = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
};

// Verify that base file permission enums are compatible with S_Ixxx. If these
// asserts ever fail, we'll need to ensure that users of these functions switch
// away from using base permission enums and add a note to the function comments
// indicating that base enums can not be used.
static_assert(base::FILE_PERMISSION_READ_BY_USER == S_IRUSR,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_WRITE_BY_USER == S_IWUSR,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_EXECUTE_BY_USER == S_IXUSR,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_READ_BY_GROUP == S_IRGRP,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_WRITE_BY_GROUP == S_IWGRP,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_EXECUTE_BY_GROUP == S_IXGRP,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_READ_BY_OTHERS == S_IROTH,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_WRITE_BY_OTHERS == S_IWOTH,
              "base file permissions don't match unistd.h permissions");
static_assert(base::FILE_PERMISSION_EXECUTE_BY_OTHERS == S_IXOTH,
              "base file permissions don't match unistd.h permissions");

enum RegularFileOrDeleteResult {
  kFailure = 0,      // Failed to delete whatever was at the path.
  kRegularFile = 1,  // Regular file existed and was unchanged.
  kEmpty = 2         // Anything that was at the path has been deleted.
};

// Checks if a regular file owned by |uid| and |gid| exists at |path|, otherwise
// deletes anything that might be at |path|. Returns a RegularFileOrDeleteResult
// enum indicating what is at |path| after the function finishes.
RegularFileOrDeleteResult RegularFileOrDelete(const base::FilePath& path,
                                              uid_t uid,
                                              gid_t gid) {
  // Check for symlinks by setting O_NOFOLLOW and checking for ELOOP. This lets
  // us use the safer fstat() instead of having to use lstat().
  base::ScopedFD scoped_fd(HANDLE_EINTR(openat(
      AT_FDCWD, path.value().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)));
  bool path_not_empty = (errno == ELOOP || scoped_fd != -1);

  // If there is a file/directory at |path|, see if it matches our criteria.
  if (scoped_fd != -1) {
    struct stat file_stat;
    if (fstat(scoped_fd.get(), &file_stat) != -1 &&
        S_ISREG(file_stat.st_mode) && file_stat.st_uid == uid &&
        file_stat.st_gid == gid) {
      return kRegularFile;
    }
  }

  // If we get here and anything was at |path|, try to delete it so we can put
  // our file there.
  if (path_not_empty) {
    if (!brillo::DeletePathRecursively(path)) {
      PLOG(WARNING) << "Failed to delete entity at \"" << path.value() << '"';
      return kFailure;
    }
  }

  return kEmpty;
}

// Handles common touch functionality but also provides an optional |fd_out|
// so that any further modifications to the file (e.g. permissions) can safely
// use the fd rather than the path. |fd_out| will only be set if a new file
// is created, otherwise it will be unchanged.
// If |fd_out| is null, this function will close the file, otherwise it's
// expected that |fd_out| will close the file when it goes out of scope.
bool TouchFileInternal(const base::FilePath& path,
                       uid_t uid,
                       gid_t gid,
                       base::ScopedFD* fd_out) {
  RegularFileOrDeleteResult result = RegularFileOrDelete(path, uid, gid);
  switch (result) {
    case kFailure:
      return false;
    case kRegularFile:
      return true;
    case kEmpty:
      break;
  }

  // base::CreateDirectory() returns true if the directory already existed.
  if (!base::CreateDirectory(path.DirName())) {
    PLOG(WARNING) << "Failed to create directory for \"" << path.value() << '"';
    return false;
  }

  // Create the file as owner-only initially.
  base::ScopedFD scoped_fd(HANDLE_EINTR(openat(
      AT_FDCWD, path.value().c_str(),
      O_RDONLY | O_NOFOLLOW | O_CREAT | O_EXCL | O_CLOEXEC, kPermissions600)));
  if (scoped_fd == -1) {
    PLOG(WARNING) << "Failed to create file \"" << path.value() << '"';
    return false;
  }

  if (fd_out) {
    *fd_out = std::move(scoped_fd);
  }
  return true;
}

std::string GetRandomSuffix() {
  const int kBufferSize = 6;
  unsigned char buffer[kBufferSize];
  base::RandBytes(buffer, std::size(buffer));
  std::string suffix;
  for (int i = 0; i < kBufferSize; ++i) {
    int random_value = buffer[i] % (2 * 26 + 10);
    if (random_value < 26) {
      suffix.push_back('a' + random_value);
    } else if (random_value < 2 * 26) {
      suffix.push_back('A' + random_value - 26);
    } else {
      suffix.push_back('0' + random_value - 2 * 26);
    }
  }
  return suffix;
}

base::ScopedFD OpenPathComponentInternal(int parent_fd,
                                         const std::string& file,
                                         int flags,
                                         mode_t mode) {
  DCHECK(file == "/" || file.find("/") == std::string::npos);
  base::ScopedFD fd;

  // O_NONBLOCK is used to avoid hanging on edge cases (e.g. a serial port with
  // flow control, or a FIFO without a writer).
  if (parent_fd >= 0 || parent_fd == AT_FDCWD) {
    fd.reset(HANDLE_EINTR(openat(parent_fd, file.c_str(),
                                 flags | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
                                 mode)));
  } else if (file == "/") {
    fd.reset(HANDLE_EINTR(open(
        file.c_str(),
        flags | O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
        mode)));
  }

  if (!fd.is_valid()) {
    // open(2) fails with ELOOP when the last component of the |path| is a
    // symlink. It fails with ENXIO when |path| is a FIFO and |flags| is for
    // writing because of the O_NONBLOCK flag added above.
    if (errno == ELOOP || errno == ENXIO) {
      PLOG(WARNING) << "Failed to open " << file << " safely.";
    } else {
      PLOG(WARNING) << "Failed to open " << file << ".";
    }
    return base::ScopedFD();
  }

  // Remove the O_NONBLOCK flag unless the original |flags| have it.
  if ((flags & O_NONBLOCK) == 0) {
    flags = fcntl(fd.get(), F_GETFL);
    if (flags == -1) {
      PLOG(ERROR) << "Failed to get fd flags for " << file;
      return base::ScopedFD();
    }
    if (fcntl(fd.get(), F_SETFL, flags & ~O_NONBLOCK)) {
      PLOG(ERROR) << "Failed to set fd flags for " << file;
      return base::ScopedFD();
    }
  }

  return fd;
}

base::ScopedFD OpenSafelyInternal(int parent_fd,
                                  const base::FilePath& path,
                                  int flags,
                                  mode_t mode) {
  std::vector<std::string> components = path.GetComponents();

  auto itr = components.begin();
  if (itr == components.end()) {
    LOG(ERROR) << "A path is required.";
    return base::ScopedFD();  // This is an invalid fd.
  }

  base::ScopedFD child_fd;
  int parent_flags = flags | O_NONBLOCK | O_RDONLY | O_DIRECTORY | O_PATH;
  for (; itr + 1 != components.end(); ++itr) {
    child_fd = OpenPathComponentInternal(parent_fd, *itr, parent_flags, 0);
    if (!child_fd.is_valid()) {
      return base::ScopedFD();
    }
    parent_fd = child_fd.get();
  }

  return OpenPathComponentInternal(parent_fd, *itr, flags, mode);
}

}  // namespace

bool TouchFile(const base::FilePath& path,
               int new_file_permissions,
               uid_t uid,
               gid_t gid) {
  // Make sure |permissions| doesn't have any out-of-range bits.
  if (new_file_permissions & ~kPermissions777) {
    LOG(WARNING) << "Illegal permissions: " << new_file_permissions;
    return false;
  }

  base::ScopedFD scoped_fd;
  if (!TouchFileInternal(path, uid, gid, &scoped_fd)) {
    return false;
  }

  // scoped_fd is valid only if a new file was created.
  if (scoped_fd != -1 &&
      HANDLE_EINTR(fchmod(scoped_fd.get(), new_file_permissions)) == -1) {
    PLOG(WARNING) << "Failed to set permissions for \"" << path.value() << '"';
    brillo::DeleteFile(path);
    return false;
  }

  return true;
}

bool TouchFile(const base::FilePath& path) {
  // Use TouchFile() instead of TouchFileInternal() to explicitly set
  // permissions to 600 in case umask is set strangely.
  return TouchFile(path, kPermissions600, geteuid(), getegid());
}

base::ScopedFD OpenSafely(const base::FilePath& path, int flags, mode_t mode) {
  if (!path.IsAbsolute()) {
    LOG(ERROR) << "An absolute path is required.";
    return base::ScopedFD();  // This is an invalid fd.
  }

  base::ScopedFD fd(OpenSafelyInternal(-1, path, flags, mode));
  if (!fd.is_valid())
    return base::ScopedFD();

  // Ensure the opened file is a regular file or directory.
  struct stat st;
  if (fstat(fd.get(), &st) < 0) {
    PLOG(ERROR) << "Failed to fstat " << path.value();
    return base::ScopedFD();
  }

  // This detects a FIFO opened for reading, for example.
  if (flags & O_DIRECTORY) {
    if (!S_ISDIR(st.st_mode)) {
      LOG(ERROR) << path.value() << " is not a directory: " << st.st_mode;
      return base::ScopedFD();
    }
  } else if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
    LOG(ERROR) << path.value()
               << " is not a regular file or directory: " << st.st_mode;
    return base::ScopedFD();
  }

  return fd;
}

base::ScopedFD OpenAtSafely(int parent_fd,
                            const base::FilePath& path,
                            int flags,
                            mode_t mode) {
  base::ScopedFD fd(OpenSafelyInternal(parent_fd, path, flags, mode));
  if (!fd.is_valid())
    return base::ScopedFD();

  // Ensure the opened file is a regular file or directory.
  struct stat st;
  if (fstat(fd.get(), &st) < 0) {
    PLOG(ERROR) << "Failed to fstat " << path.value();
    return base::ScopedFD();
  }

  // This detects a FIFO opened for reading, for example.
  if (flags & O_DIRECTORY) {
    if (!S_ISDIR(st.st_mode)) {
      LOG(ERROR) << path.value() << " is not a directory: " << st.st_mode;
      return base::ScopedFD();
    }
  } else if (!S_ISREG(st.st_mode)) {
    LOG(ERROR) << path.value() << " is not a regular file: " << st.st_mode;
    return base::ScopedFD();
  }

  return fd;
}

base::ScopedFD OpenFifoSafely(const base::FilePath& path,
                              int flags,
                              mode_t mode) {
  if (!path.IsAbsolute()) {
    LOG(ERROR) << "An absolute path is required.";
    return base::ScopedFD();  // This is an invalid fd.
  }

  base::ScopedFD fd(OpenSafelyInternal(-1, path, flags, mode));
  if (!fd.is_valid())
    return base::ScopedFD();

  // Ensure the opened file is a FIFO.
  struct stat st;
  if (fstat(fd.get(), &st) < 0) {
    PLOG(ERROR) << "Failed to fstat " << path.value();
    return base::ScopedFD();
  }

  if (!S_ISFIFO(st.st_mode)) {
    LOG(ERROR) << path.value() << " is not a FIFO: " << st.st_mode;
    return base::ScopedFD();
  }

  return fd;
}

base::ScopedFD MkdirRecursively(const base::FilePath& full_path, mode_t mode) {
  std::vector<std::string> components = full_path.GetComponents();

  auto itr = components.begin();
  if (!full_path.IsAbsolute() || itr == components.end()) {
    LOG(ERROR) << "An absolute path is required.";
    return base::ScopedFD();  // This is an invalid fd.
  }

  base::ScopedFD parent_fd;
  int parent_flags = O_NONBLOCK | O_RDONLY | O_DIRECTORY | O_PATH;
  while (itr + 1 != components.end()) {
    base::ScopedFD child(
        OpenPathComponentInternal(parent_fd.get(), *itr, parent_flags, 0));
    if (!child.is_valid()) {
      return base::ScopedFD();
    }
    parent_fd = std::move(child);

    ++itr;

    // Try to create the directory. Note that Chromium's MkdirRecursively() uses
    // 0700, but we use 0755.
    if (mkdirat(parent_fd.get(), itr->c_str(), mode) != 0) {
      if (errno != EEXIST) {
        PLOG(ERROR) << "Failed to mkdirat " << *itr
                    << ": full_path=" << full_path.value();
        return base::ScopedFD();
      }
    }
  }

  return OpenPathComponentInternal(parent_fd.get(), *itr,
                                   O_RDONLY | O_DIRECTORY, 0);
}

bool WriteStringToFile(const base::FilePath& path, const std::string& data) {
  return WriteToFile(path, data.data(), data.size());
}

bool WriteToFile(const base::FilePath& path, const char* data, size_t size) {
  if (!base::DirectoryExists(path.DirName())) {
    if (!base::CreateDirectory(path.DirName())) {
      LOG(ERROR) << "Cannot create directory: " << path.DirName().value();
      return false;
    }
  }
  // base::WriteFile takes an int size.
  if (size > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Cannot write to " << path.value()
               << ". Data is too large: " << size << " bytes.";
    return false;
  }

  int data_written = base::WriteFile(path, data, size);
  return data_written == static_cast<int>(size);
}

bool SyncFileOrDirectory(const base::FilePath& path,
                         bool is_directory,
                         bool data_sync) {
  const base::TimeTicks start = base::TimeTicks::Now();
  data_sync = data_sync && !is_directory;

  int flags = (is_directory ? O_RDONLY | O_DIRECTORY : O_WRONLY);
  int fd = HANDLE_EINTR(open(path.value().c_str(), flags));
  if (fd < 0) {
    PLOG(WARNING) << "Could not open " << path.value() << " for syncing";
    return false;
  }
  // POSIX specifies EINTR as a possible return value of fsync() but not for
  // fdatasync().  To be on the safe side, it is handled in both cases.
  int result =
      (data_sync ? HANDLE_EINTR(fdatasync(fd)) : HANDLE_EINTR(fsync(fd)));
  if (result < 0) {
    PLOG(WARNING) << "Failed to sync " << path.value();
    close(fd);
    return false;
  }
  // close() may not be retried on error.
  result = IGNORE_EINTR(close(fd));
  if (result < 0) {
    PLOG(WARNING) << "Failed to close after sync " << path.value();
    return false;
  }

  const base::TimeDelta delta = base::TimeTicks::Now() - start;
  if (delta > kLongSync) {
    LOG(WARNING) << "Long " << (data_sync ? "fdatasync" : "fsync") << "() of "
                 << path.value() << ": " << delta.InSeconds() << " seconds";
  }

  return true;
}

bool WriteToFileAtomic(const base::FilePath& path,
                       const char* data,
                       size_t size,
                       mode_t mode) {
  if (!base::DirectoryExists(path.DirName())) {
    if (!base::CreateDirectory(path.DirName())) {
      LOG(ERROR) << "Cannot create directory: " << path.DirName().value();
      return false;
    }
  }
  std::string random_suffix = GetRandomSuffix();
  if (random_suffix.empty()) {
    LOG(WARNING) << "Could not compute random suffix";
    return false;
  }
  std::string temp_name = path.AddExtension(random_suffix).value();
  int fd =
      HANDLE_EINTR(open(temp_name.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode));
  if (fd < 0) {
    PLOG(WARNING) << "Could not open " << temp_name << " for atomic write";
    unlink(temp_name.c_str());
    return false;
  }

  size_t position = 0;
  while (position < size) {
    ssize_t bytes_written =
        HANDLE_EINTR(write(fd, data + position, size - position));
    if (bytes_written < 0) {
      PLOG(WARNING) << "Could not write " << temp_name;
      close(fd);
      unlink(temp_name.c_str());
      return false;
    }
    position += bytes_written;
  }

  if (HANDLE_EINTR(fdatasync(fd)) < 0) {
    PLOG(WARNING) << "Could not fsync " << temp_name;
    close(fd);
    unlink(temp_name.c_str());
    return false;
  }
  if (close(fd) < 0) {
    PLOG(WARNING) << "Could not close " << temp_name;
    unlink(temp_name.c_str());
    return false;
  }

  if (rename(temp_name.c_str(), path.value().c_str()) < 0) {
    PLOG(WARNING) << "Could not rename " << temp_name;
    unlink(temp_name.c_str());
    return false;
  }

  return true;
}

int64_t ComputeDirectoryDiskUsage(const base::FilePath& root_path) {
  int64_t running_blocks = 0;
  base::FileEnumerator file_iter(root_path, true,
                                 base::FileEnumerator::FILES |
                                     base::FileEnumerator::DIRECTORIES |
                                     base::FileEnumerator::SHOW_SYM_LINKS);
  while (!file_iter.Next().empty()) {
    // st_blocks in struct stat is the number of S_BLKSIZE (512) bytes sized
    // blocks occupied by this file.
    running_blocks += file_iter.GetInfo().stat().st_blocks;
  }
  // Each block is S_BLKSIZE (512) bytes so *S_BLKSIZE.
  return running_blocks * S_BLKSIZE;
}

}  // namespace brillo
