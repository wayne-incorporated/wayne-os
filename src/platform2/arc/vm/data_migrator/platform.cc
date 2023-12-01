// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/platform.h"

#include <errno.h>
#include <fcntl.h>

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/platform_file.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/threading/scoped_blocking_call.h>

namespace arc::data_migrator {

namespace {

// Almost a verbatim copy of base::File::DoInitialize().
// A major difference from the original implementation is that the `created_`
// field of |file| is not properly set. This should not be a problem because
// the migrator does not check the field.
void DoInitialize(base::File* file,
                  const base::FilePath& path,
                  uint32_t flags) {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  int open_flags = 0;
  if (flags & base::File::FLAG_CREATE) {
    open_flags = O_CREAT | O_EXCL;
  }

  // created_ = false;

  if (flags & base::File::FLAG_CREATE_ALWAYS) {
    DCHECK(!open_flags);
    DCHECK(flags & base::File::FLAG_WRITE);
    open_flags = O_CREAT | O_TRUNC;
  }

  if (flags & base::File::FLAG_OPEN_TRUNCATED) {
    DCHECK(!open_flags);
    DCHECK(flags & base::File::FLAG_WRITE);
    open_flags = O_TRUNC;
  }

  if (!open_flags && !(flags & base::File::FLAG_OPEN) &&
      !(flags & base::File::FLAG_OPEN_ALWAYS)) {
    NOTREACHED();
    errno = EOPNOTSUPP;
    *file = base::File(base::File::FILE_ERROR_FAILED);
    return;
  }

  if ((flags & base::File::FLAG_WRITE) && (flags & base::File::FLAG_READ)) {
    open_flags |= O_RDWR;
  } else if (flags & base::File::FLAG_WRITE) {
    open_flags |= O_WRONLY;
  } else if (!(flags & base::File::FLAG_READ) &&
             !(flags & base::File::FLAG_WRITE_ATTRIBUTES) &&
             !(flags & base::File::FLAG_APPEND) &&
             !(flags & base::File::FLAG_OPEN_ALWAYS)) {
    // Note: For FLAG_WRITE_ATTRIBUTES and no other read/write flags, we'll
    // open the file in O_RDONLY mode (== 0, see static_assert below), so that
    // we get a fd that can be used for SetTimes().
    NOTREACHED();
  }

  if (flags & base::File::FLAG_TERMINAL_DEVICE) {
    open_flags |= O_NOCTTY | O_NDELAY;
  }

  if ((flags & base::File::FLAG_APPEND) && (flags & base::File::FLAG_READ)) {
    open_flags |= O_APPEND | O_RDWR;
  } else if (flags & base::File::FLAG_APPEND) {
    open_flags |= O_APPEND | O_WRONLY;
  }

  static_assert(O_RDONLY == 0, "O_RDONLY must equal zero");

  mode_t mode = S_IRUSR | S_IWUSR;
  // #if BUILDFLAG(IS_CHROMEOS)
  mode |= S_IRGRP | S_IROTH;
  // #endif

  int descriptor = HANDLE_EINTR(open(path.value().c_str(), open_flags, mode));

  if (flags & base::File::FLAG_OPEN_ALWAYS) {
    if (descriptor < 0) {
      open_flags |= O_CREAT;
      descriptor = HANDLE_EINTR(open(path.value().c_str(), open_flags, mode));
      // if (descriptor >= 0) {
      //   created_ = true;
      // }
    }
  }

  if (descriptor < 0) {
    *file = base::File(base::File::GetLastFileError());
    return;
  }

  // if (flags & (FLAG_CREATE_ALWAYS | FLAG_CREATE)) {
  //   created_ = true;
  // }

  if (flags & base::File::FLAG_DELETE_ON_CLOSE) {
    unlink(path.value().c_str());
  }

  const bool async = (flags & base::File::FLAG_ASYNC) == base::File::FLAG_ASYNC;
  *file = base::File(base::ScopedPlatformFile(descriptor), async);
}

}  // namespace

bool ReferencesParent(const base::FilePath& path) {
  if (path.value().find(base::FilePath::kParentDirectory) ==
      std::string::npos) {
    return false;
  }

  const std::vector<std::string> components = path.GetComponents();
  for (const auto& component : components) {
    if (component == base::FilePath::kParentDirectory) {
      return true;
    }
  }

  return false;
}

Platform::~Platform() {}

void Platform::InitializeFile(base::File* file,
                              const base::FilePath& path,
                              uint32_t flags) {
  // Try the original implementation first.
  cryptohome::Platform::InitializeFile(file, path, flags);
  if (file->IsValid() ||
      file->error_details() != base::File::FILE_ERROR_ACCESS_DENIED) {
    return;
  }

  // When Initialize() fails with FILE_ERROR_ACCESS_DENIED, first check whether
  // the path contains ".." or not.
  if (ReferencesParent(path)) {
    // The path actually references parent with "..".
    *file = base::File(base::File::FILE_ERROR_ACCESS_DENIED);
    return;
  }

  // The path is valid. Try initializing the file using our replacement for
  // base::File::DoInitialize().
  DoInitialize(file, path, flags);
}

}  // namespace arc::data_migrator
