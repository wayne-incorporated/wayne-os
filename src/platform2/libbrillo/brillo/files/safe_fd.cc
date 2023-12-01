// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/files/safe_fd.h"

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/files/file_util.h>
#include <brillo/files/scoped_dir.h>
#include <brillo/syslog_logging.h>

namespace brillo {

namespace {

SafeFD::SafeFDResult MakeErrorResult(SafeFD::Error error) {
  return std::make_pair(SafeFD(), error);
}

SafeFD::SafeFDResult MakeSuccessResult(SafeFD&& fd) {
  return std::make_pair(std::move(fd), SafeFD::Error::kNoError);
}

SafeFD::SafeFDResult OpenPathComponentInternal(int parent_fd,
                                               const std::string& file,
                                               int flags,
                                               mode_t mode) {
  if (file != "/" && file.find("/") != std::string::npos) {
    return MakeErrorResult(SafeFD::Error::kBadArgument);
  }
  SafeFD fd;

  // O_NONBLOCK is used to avoid hanging on edge cases (e.g. a serial port with
  // flow control, or a FIFO without a writer).
  if (parent_fd >= 0 || parent_fd == AT_FDCWD) {
    fd.UnsafeReset(HANDLE_EINTR(openat(parent_fd, file.c_str(),
                                       flags | O_NONBLOCK | O_NOFOLLOW, mode)));
  } else if (file == "/") {
    fd.UnsafeReset(HANDLE_EINTR(open(
        file.c_str(), flags | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW, mode)));
  }

  if (!fd.is_valid()) {
    // open(2) fails with ELOOP when the last component of the |path| is a
    // symlink. It fails with ENXIO when |path| is a FIFO and |flags| is for
    // writing because of the O_NONBLOCK flag added above.
    switch (errno) {
      case ENOENT:
        // Do not write to the log because opening a non-existent file is a
        // frequent occurrence.
        return MakeErrorResult(SafeFD::Error::kDoesNotExist);
      case ELOOP:
        // PLOG prints something along the lines of the symlink depth being too
        // great which is is misleading so LOG is used instead.
        LOG(ERROR) << "Symlink detected! failed to open \"" << file
                   << "\" safely.";
        return MakeErrorResult(SafeFD::Error::kSymlinkDetected);
      case EISDIR:
        PLOG(ERROR) << "Directory detected! failed to open \"" << file
                    << "\" safely";
        return MakeErrorResult(SafeFD::Error::kWrongType);
      case ENOTDIR:
        PLOG(ERROR) << "Not a directory! failed to open \"" << file
                    << "\" safely";
        return MakeErrorResult(SafeFD::Error::kWrongType);
      case ENXIO:
        PLOG(ERROR) << "FIFO detected! failed to open \"" << file
                    << "\" safely";
        return MakeErrorResult(SafeFD::Error::kWrongType);
      default:
        PLOG(ERROR) << "Failed to open \"" << file << '"';
        return MakeErrorResult(SafeFD::Error::kIOError);
    }
  }

  // Remove the O_NONBLOCK flag unless the original |flags| have it.
  if ((flags & O_NONBLOCK) == 0) {
    flags = fcntl(fd.get(), F_GETFL);
    if (flags == -1) {
      PLOG(ERROR) << "Failed to get fd flags for " << file;
      return MakeErrorResult(SafeFD::Error::kIOError);
    }
    if (fcntl(fd.get(), F_SETFL, flags & ~O_NONBLOCK)) {
      PLOG(ERROR) << "Failed to set fd flags for " << file;
      return MakeErrorResult(SafeFD::Error::kIOError);
    }
  }

  return MakeSuccessResult(std::move(fd));
}

SafeFD::SafeFDResult OpenSafelyInternal(int parent_fd,
                                        const base::FilePath& path,
                                        int flags,
                                        mode_t mode) {
  std::vector<std::string> components = path.GetComponents();

  auto itr = components.begin();
  if (itr == components.end()) {
    LOG(ERROR) << "A path is required.";
    return MakeErrorResult(SafeFD::Error::kBadArgument);
  }

  SafeFD::SafeFDResult child_fd;
  int parent_flags = flags | O_NONBLOCK | O_RDONLY | O_DIRECTORY | O_PATH;
  for (; itr + 1 != components.end(); ++itr) {
    child_fd = OpenPathComponentInternal(parent_fd, *itr, parent_flags, 0);
    // Operation failed, so directly return the error result.
    if (!child_fd.first.is_valid()) {
      return child_fd;
    }
    parent_fd = child_fd.first.get();
  }

  return OpenPathComponentInternal(parent_fd, *itr, flags, mode);
}

SafeFD::Error CheckAttributes(int fd,
                              mode_t permissions,
                              uid_t uid,
                              gid_t gid) {
  struct stat fd_attributes;
  if (fstat(fd, &fd_attributes) != 0) {
    PLOG(ERROR) << "fstat failed";
    return SafeFD::Error::kIOError;
  }

  if (fd_attributes.st_uid != uid) {
    LOG(ERROR) << "Owner uid is " << fd_attributes.st_uid << " instead of "
               << uid;
    return SafeFD::Error::kWrongUID;
  }

  if (fd_attributes.st_gid != gid) {
    LOG(ERROR) << "Owner gid is " << fd_attributes.st_gid << " instead of "
               << gid;
    return SafeFD::Error::kWrongGID;
  }

  if ((0777 & (fd_attributes.st_mode ^ permissions)) != 0) {
    mode_t mask = umask(0);
    umask(mask);
    LOG(ERROR) << "Permissions are " << std::oct
               << (0777 & fd_attributes.st_mode) << " instead of "
               << (0777 & permissions) << ". Umask is " << std::oct << mask
               << std::dec;
    return SafeFD::Error::kWrongPermissions;
  }

  return SafeFD::Error::kNoError;
}

SafeFD::Error GetFileSize(int fd, size_t* file_size) {
  struct stat fd_attributes;
  if (fstat(fd, &fd_attributes) != 0) {
    return SafeFD::Error::kIOError;
  }

  *file_size = fd_attributes.st_size;
  return SafeFD::Error::kNoError;
}

SafeFD::Error SeekToBeginning(int fd) {
  errno = 0;
  if (lseek(fd, 0, SEEK_SET) == -1) {
    PLOG(ERROR) << "Failed to seek file to beginning";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

SafeFD::Error WriteImpl(int fd, const char* data, size_t size) {
  errno = 0;
  if (!base::WriteFileDescriptor(fd, base::StringPiece(data, size))) {
    PLOG(ERROR) << "Failed to write to file";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

SafeFD::Error TruncateImpl(int fd, size_t size) {
  errno = 0;
  if (HANDLE_EINTR(ftruncate(fd, size)) != 0) {
    PLOG(ERROR) << "Failed to truncate file";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

// Cover the case that sendfile is not supported for |source|.
SafeFD::Error CopyContentsToFallback(SafeFD* source,
                                     SafeFD* destination,
                                     size_t max_size) {
  std::vector<char> buffer(SafeFD::kDefaultPageSize, 0);
  size_t total_copied = 0;
  while (total_copied < max_size) {
    // Use the current offset.
    ssize_t read_count =
        HANDLE_EINTR(read(source->get(), buffer.data(), buffer.size()));
    if (read_count == 0) {
      return TruncateImpl(destination->get(), total_copied);
    }
    if (read_count < 0) {
      PLOG(ERROR) << "Failed to copy file; read";
      return SafeFD::Error::kIOError;
    }

    SafeFD::Error err =
        WriteImpl(destination->get(), buffer.data(), read_count);
    if (err != SafeFD::Error::kNoError) {
      return err;
    }
    total_copied += read_count;
  }
  return SafeFD::Error::kExceededMaximum;
}

}  // namespace

bool SafeFD::IsError(SafeFD::Error err) {
  return err != Error::kNoError;
}

const char* SafeFD::RootPath = "/";

SafeFD::SafeFDResult SafeFD::Root() {
  SafeFD::SafeFDResult root =
      OpenPathComponentInternal(-1, "/", O_DIRECTORY, 0);
  if (strcmp(SafeFD::RootPath, "/") == 0) {
    return root;
  }

  if (!root.first.is_valid()) {
    LOG(ERROR) << "Failed to open root directory!";
    return root;
  }
  return root.first.OpenExistingDir(base::FilePath(SafeFD::RootPath));
}

void SafeFD::SetRootPathForTesting(const char* new_root_path) {
  SafeFD::RootPath = new_root_path;
}

int SafeFD::get() const {
  return fd_.get();
}

bool SafeFD::is_valid() const {
  return fd_.is_valid();
}

void SafeFD::reset() {
  return fd_.reset();
}

void SafeFD::UnsafeReset(int fd) {
  return fd_.reset(fd);
}

SafeFD::Error SafeFD::Replace(const char* data, size_t size) {
  if (!fd_.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  SafeFD::Error error = SeekToBeginning(fd_.get());
  if (IsError(error)) {
    return error;
  }

  error = WriteImpl(fd_.get(), data, size);
  if (IsError(error)) {
    return error;
  }

  return TruncateImpl(fd_.get(), size);
}

SafeFD::Error SafeFD::Write(const char* data, size_t size) {
  if (!fd_.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }
  return WriteImpl(fd_.get(), data, size);
}

std::pair<std::vector<char>, SafeFD::Error> SafeFD::ReadContents(
    size_t max_size) {
  std::vector<char> buffer;
  if (!fd_.is_valid()) {
    return std::make_pair(std::move(buffer), SafeFD::Error::kNotInitialized);
  }

  size_t file_size = 0;
  // This is used as an estimate for picking the buffer size.
  SafeFD::Error err = GetFileSize(fd_.get(), &file_size);
  if (IsError(err)) {
    return std::make_pair(std::move(buffer), err);
  }

  if (file_size > max_size) {
    return std::make_pair(std::move(buffer), SafeFD::Error::kExceededMaximum);
  }

  // Pseudo file systems like /proc and /sys report a zero file size even
  // though they have contents, but are at most one page, so add
  // kDefaultMaxPathDepth to cover this case and additional writes since
  // GetFileSize up to one page.
  buffer.resize(std::min(max_size, file_size + kDefaultPageSize));

  size_t total_read = 0;
  err = SafeFD::Error::kNoError;
  while (total_read < max_size) {
    ssize_t bytes_read = HANDLE_EINTR(read(
        fd_.get(), buffer.data() + total_read, buffer.size() - total_read));
    if (bytes_read == 0) {
      break;
    }
    if (bytes_read < 0) {
      PLOG(ERROR) << "Failed to read file";
      err = SafeFD::Error::kIOError;
      break;
    }
    total_read += bytes_read;

    // Grow the buffer if necessary.
    if (total_read + kDefaultPageSize > buffer.size()) {
      buffer.resize(std::min(max_size, std::max(total_read + kDefaultPageSize,
                                                buffer.capacity())),
                    0);
    }
  }
  if (IsError(err)) {
    buffer.clear();
  } else {
    buffer.resize(total_read);
  }
  return std::make_pair(std::move(buffer), err);
}

SafeFD::Error SafeFD::Read(char* data, size_t size) {
  if (!fd_.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  if (!base::ReadFromFD(fd_.get(), data, size)) {
    PLOG(ERROR) << "Failed to read file";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

std::pair<size_t, SafeFD::Error> SafeFD::ReadUntilEnd(char* data,
                                                      size_t max_size) {
  if (!fd_.is_valid()) {
    return std::make_pair(0, SafeFD::Error::kNotInitialized);
  }

  // base::ReadFromFD returns a bool so it cannot be used in cases where the
  // file size is not known like files in /proc, /sys, etc. These report zero
  // length but still have contents.
  size_t total_read = 0;
  while (total_read < max_size) {
    ssize_t bytes_read =
        HANDLE_EINTR(read(fd_.get(), data + total_read, max_size - total_read));
    if (bytes_read == 0) {
      return std::make_pair(total_read, SafeFD::Error::kNoError);
    }
    if (bytes_read < 0) {
      PLOG(ERROR) << "Failed to read file";
      return std::make_pair(total_read, SafeFD::Error::kIOError);
    }
    total_read += bytes_read;
  }
  return std::make_pair(total_read, SafeFD::Error::kNoError);
}

SafeFD::Error SafeFD::CopyContentsTo(SafeFD* destination, size_t max_size) {
  if (!fd_.is_valid() || !destination->is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  size_t total_copied = 0;
  while (total_copied < max_size) {
    // Use the current offset.
    ssize_t copied =
        HANDLE_EINTR(sendfile(destination->get(), fd_.get(), /*offset=*/nullptr,
                              /*length=*/max_size - total_copied));
    if (copied == 0) {
      return SafeFD::Error::kNoError;
    }
    if (copied < 0) {
      // Handle the case that an mmap-like operation is not available for fd_.
      if (total_copied == 0 && errno == EINVAL) {
        return CopyContentsToFallback(this, destination, max_size);
      }
      PLOG(ERROR) << "Failed to copy file";
      return SafeFD::Error::kIOError;
    }
    total_copied += copied;
  }
  return SafeFD::Error::kExceededMaximum;
}

SafeFD::SafeFDResult SafeFD::OpenExistingFile(const base::FilePath& path,
                                              int flags) {
  if (!fd_.is_valid()) {
    return MakeErrorResult(SafeFD::Error::kNotInitialized);
  }

  return OpenSafelyInternal(get(), path, flags, 0 /*mode*/);
}

SafeFD::SafeFDResult SafeFD::OpenExistingDir(const base::FilePath& path,
                                             int flags) {
  if (!fd_.is_valid()) {
    return MakeErrorResult(SafeFD::Error::kNotInitialized);
  }

  return OpenSafelyInternal(get(), path, O_DIRECTORY | flags /*flags*/,
                            0 /*mode*/);
}

SafeFD::SafeFDResult SafeFD::MakeFile(const base::FilePath& path,
                                      mode_t permissions,
                                      uid_t uid,
                                      gid_t gid,
                                      int flags) {
  if (!fd_.is_valid()) {
    return MakeErrorResult(SafeFD::Error::kNotInitialized);
  }

  // Open (and create if necessary) the parent directory.
  base::FilePath dir_name = path.DirName();
  SafeFD::SafeFDResult parent_dir;
  int parent_dir_fd = get();
  if (!dir_name.empty() &&
      dir_name.value() != base::FilePath::kCurrentDirectory) {
    // Apply execute permission where read permission are present for parent
    // directories.
    int dir_permissions = permissions | ((permissions & 0444) >> 2);
    parent_dir =
        MakeDir(dir_name, dir_permissions, uid, gid, O_RDONLY | O_CLOEXEC);
    if (!parent_dir.first.is_valid()) {
      return parent_dir;
    }
    parent_dir_fd = parent_dir.first.get();
  }

  // If file already exists, validate permissions.
  SafeFDResult file = OpenPathComponentInternal(
      parent_dir_fd, path.BaseName().value(), flags, permissions /*mode*/);
  if (file.first.is_valid()) {
    SafeFD::Error err =
        CheckAttributes(file.first.get(), permissions, uid, gid);
    if (IsError(err)) {
      return MakeErrorResult(err);
    }
    return file;
  } else if (errno != ENOENT) {
    return file;
  }

  // The file does exist, create it and set the ownership.
  file =
      OpenPathComponentInternal(parent_dir_fd, path.BaseName().value(),
                                O_CREAT | O_EXCL | flags, permissions /*mode*/);
  if (!file.first.is_valid()) {
    return file;
  }

  // We may not have permission to chown, so check the ownership first.
  SafeFD::Error err = CheckAttributes(file.first.get(), permissions, uid, gid);
  if (!IsError(err)) {
    return file;
  }

  if (HANDLE_EINTR(fchown(file.first.get(), uid, gid)) != 0) {
    PLOG(ERROR) << "Failed to set ownership in MakeFile() for \""
                << path.value() << '"';
    return MakeErrorResult(SafeFD::Error::kIOError);
  }
  return file;
}

SafeFD::SafeFDResult SafeFD::MakeDir(const base::FilePath& path,
                                     mode_t permissions,
                                     uid_t uid,
                                     gid_t gid,
                                     int flags) {
  if (!fd_.is_valid()) {
    return MakeErrorResult(SafeFD::Error::kNotInitialized);
  }

  std::vector<std::string> components = path.GetComponents();
  if (components.empty()) {
    LOG(ERROR) << "Called MakeDir() with an empty path";
    return MakeErrorResult(SafeFD::Error::kBadArgument);
  }

  // Walk the path creating directories as necessary.
  SafeFD dir;
  SafeFDResult child_dir;
  int parent_dir_fd = get();
  int dir_flags = O_NONBLOCK | O_DIRECTORY | O_PATH;
  bool made_dir = false;
  for (const auto& component : components) {
    if (mkdirat(parent_dir_fd, component.c_str(), permissions) != 0) {
      if (errno != EEXIST) {
        PLOG(ERROR) << "Failed to mkdirat() " << component << ": full_path=\""
                    << path.value() << '"';
        return MakeErrorResult(SafeFD::Error::kIOError);
      }
    } else {
      made_dir = true;
    }

    // For the last component in the path, use the flags provided by the caller.
    if (&component == &components.back()) {
      dir_flags = flags | O_DIRECTORY;
    }
    child_dir = OpenPathComponentInternal(parent_dir_fd, component, dir_flags,
                                          0 /*mode*/);
    if (!child_dir.first.is_valid()) {
      return child_dir;
    }

    dir = std::move(child_dir.first);
    parent_dir_fd = dir.get();
  }

  if (made_dir) {
    // We may not have permission to chown, so check the ownership first.
    SafeFD::Error err = CheckAttributes(dir.get(), permissions, uid, gid);
    if (!IsError(err)) {
      return MakeSuccessResult(std::move(dir));
    }

    // If the directory was created, set the ownership.
    if (HANDLE_EINTR(fchown(dir.get(), uid, gid)) != 0) {
      PLOG(ERROR) << "Failed to set ownership in MakeDir() for \""
                  << path.value() << '"';
      return MakeErrorResult(SafeFD::Error::kIOError);
    }
  }
  // If the directory already existed, validate the permissions.
  SafeFD::Error err = CheckAttributes(dir.get(), permissions, uid, gid);
  if (IsError(err)) {
    return MakeErrorResult(err);
  }

  return MakeSuccessResult(std::move(dir));
}

SafeFD::Error SafeFD::Link(const SafeFD& source_dir,
                           const std::string& source_name,
                           const std::string& destination_name) {
  if (!fd_.is_valid() || !source_dir.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  SafeFD::Error err = IsValidFilename(source_name);
  if (IsError(err)) {
    return err;
  }

  err = IsValidFilename(destination_name);
  if (IsError(err)) {
    return err;
  }

  if (HANDLE_EINTR(linkat(source_dir.get(), source_name.c_str(), fd_.get(),
                          destination_name.c_str(), 0)) != 0) {
    PLOG(ERROR) << "Failed to link \"" << destination_name << "\"";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

SafeFD::Error SafeFD::Unlink(const std::string& name) {
  if (!fd_.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  SafeFD::Error err = IsValidFilename(name);
  if (IsError(err)) {
    return err;
  }

  if (HANDLE_EINTR(unlinkat(fd_.get(), name.c_str(), 0 /*flags*/)) != 0) {
    // Callers can best handle whether to complain about ENOENT.
    PLOG_IF(ERROR, errno != ENOENT) << "Failed to unlink \"" << name << "\"";
    return SafeFD::Error::kIOError;
  }
  return SafeFD::Error::kNoError;
}

SafeFD::Error SafeFD::Rmdir(const std::string& name,
                            bool recursive,
                            size_t max_depth,
                            bool keep_going) {
  if (!fd_.is_valid()) {
    return SafeFD::Error::kNotInitialized;
  }

  if (max_depth == 0) {
    return SafeFD::Error::kExceededMaximum;
  }

  SafeFD::Error err = IsValidFilename(name);
  if (IsError(err)) {
    return err;
  }

  SafeFD::Error last_err = SafeFD::Error::kNoError;

  if (recursive) {
    SafeFD dir_fd;
    std::tie(dir_fd, err) =
        OpenPathComponentInternal(fd_.get(), name, O_DIRECTORY, 0);
    if (!dir_fd.is_valid()) {
      return err;
    }

    // The ScopedDIR takes ownership of this so dup_fd is not scoped on its own.
    int dup_fd = dup(dir_fd.get());
    if (dup_fd < 0) {
      PLOG(ERROR) << "dup failed";
      return SafeFD::Error::kIOError;
    }

    ScopedDIR dir(fdopendir(dup_fd));
    if (!dir.is_valid()) {
      PLOG(ERROR) << "fdopendir failed";
      close(dup_fd);
      return SafeFD::Error::kIOError;
    }

    struct stat dir_info;
    if (fstat(dir_fd.get(), &dir_info) != 0) {
      return SafeFD::Error::kIOError;
    }

    errno = 0;
    const dirent* entry = HANDLE_EINTR_IF_EQ(readdir(dir.get()), nullptr);
    while (entry != nullptr) {
      SafeFD::Error err = [&]() {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
          return SafeFD::Error::kNoError;
        }

        struct stat child_info;
        if (fstatat(dir_fd.get(), entry->d_name, &child_info,
                    AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) != 0) {
          return SafeFD::Error::kIOError;
        }

        if (child_info.st_dev != dir_info.st_dev) {
          return SafeFD::Error::kBoundaryDetected;
        }

        if (entry->d_type != DT_DIR) {
          return dir_fd.Unlink(entry->d_name);
        }

        return dir_fd.Rmdir(entry->d_name, true, max_depth - 1, keep_going);
      }();

      if (err == SafeFD::Error::kIOError && errno == ENOENT) {
        // Ignore this error since it means the child entry is gone.
      } else if (IsError(err)) {
        if (!keep_going) {
          return err;
        }
        last_err = err;
      }

      errno = 0;
      entry = HANDLE_EINTR_IF_EQ(readdir(dir.get()), nullptr);
    }
    if (errno != 0) {
      PLOG(ERROR) << "readdir failed";
      return SafeFD::Error::kIOError;
    }
  }

  if (HANDLE_EINTR(unlinkat(fd_.get(), name.c_str(), AT_REMOVEDIR)) != 0) {
    if (errno == ENOTDIR) {
      // In brillo::DeleteFile we use both Rmdir and Unlink with an expectation
      // that it will fail for files, so don't log here.
      return SafeFD::Error::kWrongType;
    } else {
      PLOG(ERROR) << "unlinkat failed";
    }
    // If there was an error during the recursive delete, we expect unlink
    // to fail with ENOTEMPTY and we bubble the error from recursion
    // instead.
    if (IsError(last_err) && errno == ENOTEMPTY) {
      return last_err;
    }
    return SafeFD::Error::kIOError;
  }

  return last_err;
}

}  // namespace brillo
