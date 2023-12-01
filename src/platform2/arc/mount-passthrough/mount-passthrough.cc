/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define FUSE_USE_VERSION 26

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse/fuse.h>
#include <fuse/fuse_common.h>
#include <fuse/fuse_lowlevel.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>

#define USER_NS_SHIFT 655360
#define CHRONOS_UID 1000
#define CHRONOS_GID 1000

#define WRAP_FS_CALL(res) ((res) < 0 ? -errno : 0)

namespace {

// Android UID and GID values are taken from
// system/core/libcutils/include/private/android_filesystem_config.h in the
// Android codebase.
constexpr uid_t kAndroidRootUid = 0;
constexpr uid_t kAndroidMediaRwUid = 1023;
constexpr uid_t kAndroidAppUidStart = 10000;
constexpr uid_t kAndroidAppUidEnd = 19999;
constexpr uid_t kAndroidAppUidStartInCrOS = kAndroidAppUidStart + USER_NS_SHIFT;
constexpr uid_t kAndroidAppUidEndInCrOS = kAndroidAppUidEnd + USER_NS_SHIFT;

constexpr gid_t kAndroidSdcardGid = 1015;
constexpr gid_t kAndroidMediaRwGid = 1023;
constexpr gid_t kAndroidExternalStorageGid = 1077;
constexpr gid_t kAndroidEverybodyGid = 9997;

constexpr char kCrosMountPassthroughFsContext[] =
    "u:object_r:cros_mount_passthrough_fs:s0";
constexpr char kMediaRwDataFileContext[] = "u:object_r:media_rw_data_file:s0";

struct FusePrivateData {
  std::string android_app_access_type;
  base::FilePath root;
};

// Given android_app_access_type, figure out the source of /storage mount in
// Android.
std::string get_storage_source(const std::string& android_app_access_type) {
  std::string storage_source;
  // Either full (if no Android permission check is needed), read (for Android
  // READ_EXTERNAL_STORAGE permission check), or write (for Android
  // WRITE_EXTERNAL_STORAGE_PERMISSION).
  if (android_app_access_type == "full") {
    return std::string();
  } else if (android_app_access_type == "read") {
    return "/runtime/read";
  } else if (android_app_access_type == "write") {
    return "/runtime/write";
  } else {
    NOTREACHED();
    return "notreached";
  }
}

// Perform the following checks (only for Android apps):
// 1. if android_app_access_type is read, checks if READ_EXTERNAL_STORAGE
// permission is granted
// 2. if android_app_access_type is write, checks if WRITE_EXTERNAL_STORAGE
// permission is granted
// 3. if android_app_access_type is full, performs no check.
// Caveat: This method is implemented based on Android storage permission that
// uses mount namespace. If Android changes their permission in the future
// release, than this method needs to be adjusted.
int check_allowed() {
  fuse_context* context = fuse_get_context();
  // We only check Android app process for the Android external storage
  // permissions. Other kind of permissions (such as uid/gid) should be checked
  // through the standard Linux permission checks.
  if (context->uid < kAndroidAppUidStartInCrOS ||
      context->uid > kAndroidAppUidEndInCrOS) {
    return 0;
  }

  std::string storage_source =
      get_storage_source(static_cast<FusePrivateData*>(context->private_data)
                             ->android_app_access_type);
  // No check is required because the android_app_access_type is "full".
  if (storage_source.empty()) {
    return 0;
  }

  std::string mountinfo_path =
      base::StringPrintf("/proc/%d/mountinfo", context->pid);
  std::ifstream in(mountinfo_path);
  if (!in.is_open()) {
    PLOG(ERROR) << "Failed to open " << mountinfo_path;
    return -EPERM;
  }
  while (!in.eof()) {
    std::string line;
    std::getline(in, line);
    if (in.bad()) {
      return -EPERM;
    }
    std::vector<std::string> tokens = base::SplitString(
        line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    if (tokens.size() < 5) {
      continue;
    }
    std::string source = tokens[3];
    std::string target = tokens[4];
    if (source == storage_source && target == "/storage") {
      return 0;
    }
  }
  return -EPERM;
}

// Converts the given relative path to an absolute path.
base::FilePath GetAbsolutePath(const char* path) {
  DCHECK_EQ(path[0], '/');
  return static_cast<FusePrivateData*>(fuse_get_context()->private_data)
      ->root.Append(path + 1);
}

int passthrough_create(const char* path,
                       mode_t mode,
                       struct fuse_file_info* fi) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }

  // Ignore specified |mode| and always use a fixed mode since we do not allow
  // chmod anyway. Note that we explicitly set the umask in main().
  int fd = open(GetAbsolutePath(path).value().c_str(), fi->flags, 0644);
  if (fd < 0) {
    return -errno;
  }
  fi->fh = fd;
  return 0;
}

int passthrough_fgetattr(const char*,
                         struct stat* buf,
                         struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  // File owner is overridden by uid/gid options passed to fuse.
  return WRAP_FS_CALL(fstat(fd, buf));
}

int passthrough_fsync(const char*, int datasync, struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  return datasync ? WRAP_FS_CALL(fdatasync(fd)) : WRAP_FS_CALL(fsync(fd));
}

int passthrough_fsyncdir(const char*, int datasync, struct fuse_file_info* fi) {
  DIR* dirp = reinterpret_cast<DIR*>(fi->fh);
  int fd = dirfd(dirp);
  return datasync ? WRAP_FS_CALL(fdatasync(fd)) : WRAP_FS_CALL(fsync(fd));
}

int passthrough_ftruncate(const char*, off_t size, struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  return WRAP_FS_CALL(ftruncate(fd, size));
}

int passthrough_getattr(const char* path, struct stat* buf) {
  // File owner is overridden by uid/gid options passed to fuse.
  // Unfortunately, we dont have check_allowed() here because getattr is called
  // by kernel VFS during fstat (which receives fd). We couldn't prohibit such
  // fd calls to happen, so we need to relax this.
  return WRAP_FS_CALL(lstat(GetAbsolutePath(path).value().c_str(), buf));
}

int passthrough_getxattr(const char* path,
                         const char* name,
                         char* value,
                         size_t size) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(
      lgetxattr(GetAbsolutePath(path).value().c_str(), name, value, size));
}

int passthrough_ioctl(const char*,
                      int cmd,
                      void* arg,
                      struct fuse_file_info* fi,
                      unsigned int flags,
                      void* data) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  // NOTE: We don't check if FUSE_IOCTL_COMPAT is included in the flags because
  // currently all supported ioctl commands are not affected by the difference
  // between 32-bit and 64-bit.
  int fd = static_cast<int>(fi->fh);
  switch (static_cast<unsigned int>(cmd)) {
    case FS_IOC_FSGETXATTR:
      return WRAP_FS_CALL(ioctl(fd, FS_IOC_FSGETXATTR, data));
    case FS_IOC_FSSETXATTR:
      return WRAP_FS_CALL(ioctl(fd, FS_IOC_FSSETXATTR, data));
    default:
      return -ENOTTY;
  }
}

int passthrough_mkdir(const char* path, mode_t mode) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }

  return WRAP_FS_CALL(mkdir(GetAbsolutePath(path).value().c_str(), mode));
}

int passthrough_open(const char* path, struct fuse_file_info* fi) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  int fd = open(GetAbsolutePath(path).value().c_str(), fi->flags);
  if (fd < 0) {
    return -errno;
  }
  fi->fh = fd;
  return 0;
}

int passthrough_opendir(const char* path, struct fuse_file_info* fi) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  DIR* dirp = opendir(GetAbsolutePath(path).value().c_str());
  if (!dirp) {
    return -errno;
  }
  fi->fh = reinterpret_cast<uint64_t>(dirp);
  return 0;
}

int passthrough_read(
    const char*, char* buf, size_t size, off_t off, struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  int res = pread(fd, buf, size, off);
  if (res < 0) {
    return -errno;
  }
  return res;
}

int passthrough_read_buf(const char*,
                         struct fuse_bufvec** srcp,
                         size_t size,
                         off_t off,
                         struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  struct fuse_bufvec* src =
      static_cast<struct fuse_bufvec*>(malloc(sizeof(struct fuse_bufvec)));
  *src = FUSE_BUFVEC_INIT(size);
  src->buf[0].flags =
      static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
  src->buf[0].fd = fd;
  src->buf[0].pos = off;
  *srcp = src;
  return 0;
}

int passthrough_readdir(const char*,
                        void* buf,
                        fuse_fill_dir_t filler,
                        off_t off,
                        struct fuse_file_info* fi) {
  // TODO(b/202085840): This implementation returns all files at once and thus
  // inefficient. Make use of offset and be better to memory.
  DIR* dirp = reinterpret_cast<DIR*>(fi->fh);
  // Call rewinddir so that all entries are added by filler every time this
  // function is called.
  rewinddir(dirp);
  errno = 0;
  for (;;) {
    struct dirent* entry = readdir(dirp);
    if (entry == nullptr) {
      break;
    }
    // Only IF part of st_mode matters. See fill_dir() in fuse.c.
    struct stat stbuf = {};
    stbuf.st_mode = DTTOIF(entry->d_type);
    filler(buf, entry->d_name, &stbuf, 0);
  }
  return -errno;
}

int passthrough_release(const char*, struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  return WRAP_FS_CALL(close(fd));
}

int passthrough_releasedir(const char*, struct fuse_file_info* fi) {
  DIR* dirp = reinterpret_cast<DIR*>(fi->fh);
  return WRAP_FS_CALL(closedir(dirp));
}

int passthrough_rename(const char* oldpath, const char* newpath) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(rename(GetAbsolutePath(oldpath).value().c_str(),
                             GetAbsolutePath(newpath).value().c_str()));
}

int passthrough_rmdir(const char* path) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(rmdir(GetAbsolutePath(path).value().c_str()));
}

int passthrough_statfs(const char* path, struct statvfs* buf) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(statvfs(GetAbsolutePath(path).value().c_str(), buf));
}

int passthrough_truncate(const char* path, off_t size) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(truncate(GetAbsolutePath(path).value().c_str(), size));
}

int passthrough_unlink(const char* path) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(unlink(GetAbsolutePath(path).value().c_str()));
}

int passthrough_utimens(const char* path, const struct timespec tv[2]) {
  int check_allowed_result = check_allowed();
  if (check_allowed_result < 0) {
    return check_allowed_result;
  }
  return WRAP_FS_CALL(
      utimensat(AT_FDCWD, GetAbsolutePath(path).value().c_str(), tv, 0));
}

int passthrough_write(const char*,
                      const char* buf,
                      size_t size,
                      off_t off,
                      struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  int res = pwrite(fd, buf, size, off);
  if (res < 0) {
    return -errno;
  }
  return res;
}

int passthrough_write_buf(const char*,
                          struct fuse_bufvec* src,
                          off_t off,
                          struct fuse_file_info* fi) {
  int fd = static_cast<int>(fi->fh);
  struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(src));
  dst.buf[0].flags =
      static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
  dst.buf[0].fd = fd;
  dst.buf[0].pos = off;
  return fuse_buf_copy(&dst, src, static_cast<fuse_buf_copy_flags>(0));
}

void setup_passthrough_ops(struct fuse_operations* passthrough_ops) {
  memset(passthrough_ops, 0, sizeof(*passthrough_ops));
#define FILL_OP(name) passthrough_ops->name = passthrough_##name
  FILL_OP(create);
  FILL_OP(fgetattr);
  FILL_OP(fsync);
  FILL_OP(fsyncdir);
  FILL_OP(ftruncate);
  FILL_OP(getattr);
  FILL_OP(getxattr);
  FILL_OP(ioctl);
  FILL_OP(mkdir);
  FILL_OP(open);
  FILL_OP(opendir);
  FILL_OP(read);
  FILL_OP(read_buf);
  FILL_OP(readdir);
  FILL_OP(release);
  FILL_OP(releasedir);
  FILL_OP(rename);
  FILL_OP(rmdir);
  FILL_OP(statfs);
  FILL_OP(truncate);
  FILL_OP(unlink);
  FILL_OP(utimens);
  FILL_OP(write);
  FILL_OP(write_buf);
#undef FILL_OP
  passthrough_ops->flag_nullpath_ok = 1;
  passthrough_ops->flag_nopath = 1;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_string(source, "", "Source path of FUSE mount (required)");
  DEFINE_string(dest, "", "Target path of FUSE mount (required)");
  DEFINE_string(fuse_umask, "",
                "Umask to set filesystem permissions in FUSE (required)");
  DEFINE_int32(fuse_uid, -1, "UID set as file owner in FUSE (required)");
  DEFINE_int32(fuse_gid, -1, "GID set as file group in FUSE (required)");
  DEFINE_string(
      android_app_access_type, "",
      "What type of permission checks should be done for Android apps."
      " Must be either full, read, or write (required)");
  DEFINE_bool(use_default_selinux_context, false,
              "Use the default \"fuse\" SELinux context");
  DEFINE_int32(
      media_provider_uid, -1,
      "UID of Android's MediaProvider "
      "(required in Android R+ for setting non-default SELinux context)");

  // Use "arc-" prefix so that the log is recorded in /var/log/arc.log.
  brillo::OpenLog("arc-mount-passthrough", true /*log_pid*/);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  brillo::FlagHelper::Init(argc, argv, "mount-passthrough");

  if (FLAGS_source.empty()) {
    LOG(ERROR) << "--source must be specified.";
    return 1;
  }
  if (FLAGS_dest.empty()) {
    LOG(ERROR) << "--dest must be specified.";
    return 1;
  }
  if (FLAGS_fuse_umask.empty()) {
    LOG(ERROR) << "--fuse_umask must be specified.";
    return 1;
  }
  // TODO(b/286238422): Replace USE_ARC_CONTAINER_P with USE_ARCPP when we start
  // properly setting up R container.
  if (USE_ARC_CONTAINER_P) {
    if (FLAGS_fuse_uid != kAndroidRootUid &&
        FLAGS_fuse_uid != kAndroidMediaRwUid) {
      LOG(ERROR) << "Invalid FUSE file system UID: " << FLAGS_fuse_uid;
      return 1;
    }
    if (FLAGS_fuse_gid != kAndroidSdcardGid &&
        FLAGS_fuse_gid != kAndroidMediaRwGid &&
        FLAGS_fuse_gid != kAndroidEverybodyGid) {
      LOG(ERROR) << "Invalid FUSE file system GID: " << FLAGS_fuse_gid;
      return 1;
    }
  } else {
    if (FLAGS_fuse_uid < kAndroidAppUidStart ||
        FLAGS_fuse_uid > kAndroidAppUidEnd) {
      LOG(ERROR) << "Invalid FUSE file system UID: " << FLAGS_fuse_uid;
      return 1;
    }
    if (FLAGS_fuse_gid != kAndroidExternalStorageGid) {
      LOG(ERROR) << "Invalid FUSE file system GID: " << FLAGS_fuse_gid;
      return 1;
    }
  }
  if (FLAGS_android_app_access_type.empty()) {
    LOG(ERROR) << "--android_app_access_type must be specified.";
    return 1;
  }
  if (FLAGS_android_app_access_type != "full" &&
      FLAGS_android_app_access_type != "read" &&
      FLAGS_android_app_access_type != "write") {
    LOG(ERROR) << "Invalid android_app_access_type: "
               << FLAGS_android_app_access_type
               << ". It must be either full, read, or write.";
    return 1;
  }
  if (!USE_ARC_CONTAINER_P && !FLAGS_use_default_selinux_context) {
    // MediaProvider UID needs to be specified in R+ to calculate the
    // non-default SELinux context.
    if (FLAGS_media_provider_uid < kAndroidAppUidStart ||
        FLAGS_media_provider_uid > kAndroidAppUidEnd) {
      LOG(ERROR) << "Invalid MediaProvider UID: " << FLAGS_media_provider_uid;
      return 1;
    }
  }

  if (getuid() != CHRONOS_UID) {
    LOG(ERROR) << "This daemon must run as chronos user.";
    return 1;
  }

  if (getgid() != CHRONOS_GID) {
    LOG(ERROR) << "This daemon must run as chronos group.";
    return 1;
  }

  const uid_t fuse_uid = FLAGS_fuse_uid + USER_NS_SHIFT;
  const gid_t fuse_gid = FLAGS_fuse_gid + USER_NS_SHIFT;

  struct fuse_operations passthrough_ops;
  setup_passthrough_ops(&passthrough_ops);

  const std::string fuse_uid_opt("uid=" + std::to_string(fuse_uid));
  const std::string fuse_gid_opt("gid=" + std::to_string(fuse_gid));
  const std::string fuse_umask_opt("umask=" + FLAGS_fuse_umask);
  LOG(INFO) << "uid_opt(" << fuse_uid_opt << ") "
            << "gid_opt(" << fuse_gid_opt << ") "
            << "umask_opt(" << fuse_umask_opt << ")";

  std::vector<std::string> fuse_args({
      argv[0],
      FLAGS_dest,
      "-f",
      "-o",
      "allow_other",
      "-o",
      "default_permissions",
      // Never cache attr/dentry since our backend storage is not exclusive to
      // this process.
      "-o",
      "attr_timeout=0",
      "-o",
      "entry_timeout=0",
      "-o",
      "negative_timeout=0",
      "-o",
      "ac_attr_timeout=0",
      "-o",
      "fsname=passthrough",
      "-o",
      fuse_uid_opt,
      "-o",
      fuse_gid_opt,
      "-o",
      "direct_io",
      "-o",
      fuse_umask_opt,
      "-o",
      "noexec",
  });

  if (!FLAGS_use_default_selinux_context) {
    // NOTE: Commas are escaped by "\\" to avoid being processed by lifuse's
    // option parsing code.
    std::string security_context;
    if (USE_ARC_CONTAINER_P) {
      // In Android P, the security context of directories under /data/media/0
      // is "u:object_r:media_rw_data_file:s0:c512,c768".
      security_context = std::string(kMediaRwDataFileContext) + ":c512\\,c768";
    } else {
      // In Android R, the security context of directories under /data/media/0
      // looks like "u:object_r:media_rw_data_file:s0:c64,c256,c512,c768".
      //
      // Calculate the categories in the same way as set_range_from_level() in
      // Android's external/selinux/libselinux/src/android/android_platform.c.
      const uid_t media_provider_app_id =
          FLAGS_media_provider_uid - kAndroidAppUidStart;
      security_context =
          std::string(kMediaRwDataFileContext) +
          base::StringPrintf(":c%d\\,c%d\\,c512\\,c768",
                             media_provider_app_id & 0xff,
                             256 + ((media_provider_app_id >> 8) & 0xff));
    }

    // The context string is quoted using "\"" so that the kernel won't split
    // the mount option string at commas.
    std::string fuse_context_opt(std::string("context=\"") + security_context +
                                 "\"");
    std::string fuse_fscontext_opt(std::string("fscontext=") +
                                   kCrosMountPassthroughFsContext);
    fuse_args.push_back("-o");
    fuse_args.push_back(std::move(fuse_context_opt));
    fuse_args.push_back("-o");
    fuse_args.push_back(std::move(fuse_fscontext_opt));
  }

  umask(0022);

  FusePrivateData private_data;
  private_data.android_app_access_type = FLAGS_android_app_access_type;
  private_data.root = base::FilePath(FLAGS_source);

  std::vector<const char*> fuse_argv(fuse_args.size());
  std::transform(
      fuse_args.begin(), fuse_args.end(), std::begin(fuse_argv),
      [](const std::string& arg) -> const char* { return arg.c_str(); });

  // The code below does the same thing as fuse_main() except that it ignores
  // signals during shutdown to perform clean shutdown. b/183343552
  // TODO(hashimoto): Stop using deprecated libfuse functions b/185322557.
  char* mountpoint = nullptr;
  int multithreaded = 0;
  struct fuse* fuse = fuse_setup(
      fuse_argv.size(), const_cast<char**>(fuse_argv.data()), &passthrough_ops,
      sizeof(passthrough_ops), &mountpoint, &multithreaded, &private_data);
  if (fuse == nullptr)
    return 1;

  int res = 0;
  if (multithreaded)
    res = fuse_loop_mt(fuse);
  else
    res = fuse_loop(fuse);

  // The code below does the same thing fuse_teardown() except that it ignores
  // signals instead of calling fuse_remove_signal_handlers().

  // Ignore signals after this point. We're already shutting down.
  struct sigaction sa = {};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = SIG_IGN;
  sigaction(SIGHUP, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGPIPE, &sa, nullptr);

  struct fuse_session* se = fuse_get_session(fuse);
  struct fuse_chan* ch = fuse_session_next_chan(se, nullptr);
  fuse_unmount(mountpoint, ch);
  fuse_destroy(fuse);
  free(mountpoint);

  return res == -1 ? 1 : 0;
}
