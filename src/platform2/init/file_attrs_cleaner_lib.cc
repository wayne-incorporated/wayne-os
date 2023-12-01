// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/file_attrs_cleaner.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/fs.h>

#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace file_attrs_cleaner {

namespace {

struct ScopedDirDeleter {
  inline void operator()(DIR* dirp) const {
    if (dirp)
      closedir(dirp);
  }
};
using ScopedDir = std::unique_ptr<DIR, ScopedDirDeleter>;

bool CheckSucceeded(AttributeCheckStatus status) {
  return status == AttributeCheckStatus::NO_ATTR ||
         status == AttributeCheckStatus::CLEARED;
}

}  // namespace

AttributeCheckStatus CheckFileAttributes(const base::FilePath& path,
                                         bool isdir,
                                         int fd) {
  long flags;  // NOLINT(runtime/int)
  if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != 0) {
    PLOG(WARNING) << "Getting flags failed";
    return AttributeCheckStatus::ERROR;
  }

  if (flags & FS_IMMUTABLE_FL) {
    LOG(WARNING) << "Immutable bit found, clearing it";
    flags &= ~FS_IMMUTABLE_FL;
    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) != 0) {
      PLOG(ERROR) << "Unable to clear immutable bit";
      return AttributeCheckStatus::CLEAR_FAILED;
    }
    return AttributeCheckStatus::CLEARED;
  }

  // The other file attribute flags look benign at this point.
  return AttributeCheckStatus::NO_ATTR;
}

bool ScanDir(const base::FilePath& dir,
             const std::vector<std::string>& skip_recurse) {
  // Internally glibc will use O_CLOEXEC when opening the directory.
  // Unfortunately, there is no opendirat() helper we could use (so that ScanDir
  // could accept a fd argument).
  //
  // We could use openat() ourselves and pass that to fdopendir(), but that has
  // two downsides: (1) We can't use ScopedFD because opendir() will take over
  // the fd -- when closedir() is called, close() will also be called.  We can't
  // skip the closedir() because we need to let the C library release resources
  // associated with the DIR* handle.  (2) When using fdopendir(), glibc will
  // use fcntl() to make sure O_CLOEXEC is set even if we set it ourselves when
  // we called openat().  It works, but adds a bit of syscall overhead here.
  // Along those lines, we could dup() the fd passed in, but that would also add
  // syscall overhead with no real benefit.
  //
  // So unless we change the signature of ScanDir to take a fd of the open dir
  // to scan, we stick with opendir() here.  Since this program only runs during
  // early OS init, there shouldn't be other programs in the system racing with
  // us to cause problems.

  ScopedDir dirp(opendir(dir.value().c_str()));
  if (dirp.get() == nullptr) {
    PLOG(WARNING) << "Unable to open directory";
    // This is a best effort routine so don't fail if the directory cannot be
    // opened.
    return true;
  }

  int dfd = dirfd(dirp.get());
  if (!CheckSucceeded(CheckFileAttributes(dir, true /*isdir*/, dfd))) {
    // This should never really fail...
    return false;
  }

  // We might need this if we descend into a subdir.  But if it's a leaf
  // directory (no subdirs), we can skip the stat overhead entirely.
  bool have_dirst = false;
  struct stat dirst;

  // Scan all the entries in this directory.
  bool ret = true;
  struct dirent* de;
  std::vector<base::FilePath> subdirs;
  while ((de = readdir(dirp.get())) != nullptr) {
    CHECK(de->d_type != DT_UNKNOWN);

    // Skip symlinks.
    if (de->d_type == DT_LNK)
      continue;

    // Skip the . and .. fake directories.
    const std::string_view name(de->d_name);
    if (name == "." || name == "..")
      continue;

    // If the path component is listed in |skip_recurse|, skip it.
    if (std::find(skip_recurse.begin(), skip_recurse.end(), name) !=
        skip_recurse.end())
      continue;

    const base::FilePath path = dir.Append(de->d_name);
    switch (de->d_type) {
      case DT_DIR: {
        // Don't cross mountpoints.
        if (!have_dirst) {
          // Load this on demand so leaf dirs don't waste time.
          have_dirst = true;
          if (fstat(dfd, &dirst) != 0) {
            PLOG(ERROR) << "Unable to stat dir";
            ret = false;
            continue;
          }
        }

        struct stat subdirst;
        if (fstatat(dfd, de->d_name, &subdirst, 0) != 0) {
          PLOG(ERROR) << "Unable to stat subdir";
          ret = false;
          continue;
        }

        if (dirst.st_dev != subdirst.st_dev) {
          DVLOG(1) << "Skipping mounted directory " << path.value();
          continue;
        }

        // Enqueue this directory for recursing.
        // Recursing here is problematic because it means that |dirp| remains
        // open for the lifetime of the process. Having a handle to the
        // directory open for that long causes problems if the tool is still
        // running when a user logs in. This can happen if the user has a lot of
        // files in their home directory.
        subdirs.push_back(path);
        break;
      }
      case DT_REG: {
        // Check the settings on this file.
        base::ScopedFD fd(openat(
            dfd, de->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));

        if (!fd.is_valid()) {
          // This routine can be executed over encrypted filesystems.
          // ENOKEY is normal for encrypted files, so don't log in that case.
          // We might be running in parallel with other programs which might
          // delete paths on the fly, so ignore ENOENT too.
          if (errno != ENOKEY || errno != ENOENT)
            PLOG(WARNING) << "Skipping path";

          // This is a best effort routine so don't fail if the path cannot be
          // opened.
          continue;
        }

        ret &= CheckSucceeded(
            CheckFileAttributes(path, false /*is_dir*/, fd.get()));

        break;
      }
      case DT_FIFO:
      case DT_CHR:
      case DT_BLK:
      case DT_LNK:
      case DT_SOCK:
      case DT_WHT:
        // no action needed.
        break;
      default:
        LOG(WARNING) << "Skipping path due to unsupported type " << de->d_type;
        break;
    }
  }

  if (closedir(dirp.release()) != 0)
    PLOG(ERROR) << "Unable to close directory";

  return ret;
}

}  // namespace file_attrs_cleaner
