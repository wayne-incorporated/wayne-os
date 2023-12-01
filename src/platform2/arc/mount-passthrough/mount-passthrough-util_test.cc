// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <brillo/flag_helper.h>
#include <gtest/gtest.h>

#include "arc/mount-passthrough/mount-passthrough-util.h"

namespace arc {

// Unit testing with brillo::FlagHelper and base::CommandLine requires
// some setup as those things touch global states. This is based on
// brillo/flag_helper_test.cc.
class MountPassthroughUtilTest : public ::testing::Test {
 public:
  MountPassthroughUtilTest() {}
  ~MountPassthroughUtilTest() override {
    brillo::FlagHelper::ResetForTesting();
  }

  static void SetUpTestCase() { base::CommandLine::Init(0, nullptr); }

  // Returns the front value, and erases it.
  std::string PopFront(std::vector<std::string>& list) {
    if (list.empty()) {
      return "<not enough args>";
    }
    std::string value = list.front();
    list.erase(list.begin());
    return value;
  }
};

// On VM, MyFiles and /media/removable are very similar (only --source and
// --dest are different), thus only MyFiles is tested.
TEST_F(MountPassthroughUtilTest, VmMyFiles) {
  // From arc/vm/media-sharing-services/init/arcvm-mount-myfiles.conf.
  const char* argv[] = {
      "mount-passthrough-jailed",
      "--source=/home/user/2d6fef33bb331bb08f3ca9d4db7078d776a251a6/MyFiles",
      "--dest=/run/arcvm/media/MyFiles",
      "--fuse_umask=007",
      "--fuse_uid=10058",
      "--fuse_gid=1077",
      "--media_provider_uid=10058",
      "--enter_concierge_namespace",
      "--max_number_of_open_fds=262144",
  };

  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  auto args = CreateMinijailCommandLineArgs(flags);

  EXPECT_EQ("/sbin/minijail0", PopFront(args));

  // Enter the concierge namespace.
  EXPECT_EQ("-V", PopFront(args));
  EXPECT_EQ("/run/namespaces/mnt_concierge", PopFront(args));

  // Enter a new cgroup namespace.
  EXPECT_EQ("-N", PopFront(args));

  // Enter a new UTS namespace.
  EXPECT_EQ("--uts", PopFront(args));

  // Enter a new VFS namespace and remount /proc read-only.
  EXPECT_EQ("-v", PopFront(args));
  EXPECT_EQ("-r", PopFront(args));

  // Enter a new network namespace.
  EXPECT_EQ("-e", PopFront(args));

  // Enter a new IPC namespace.
  EXPECT_EQ("-l", PopFront(args));

  // Grant CAP_SYS_ADMIN needed to mount FUSE filesystem.
  EXPECT_EQ("-c", PopFront(args));
  EXPECT_EQ("cap_sys_admin+eip", PopFront(args));

  // Set uid and gid of the daemon as chronos.
  EXPECT_EQ("-u", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-g", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));

  // Inherit supplementary groups.
  EXPECT_EQ("-G", PopFront(args));

  // Allow sharing mounts between CrOS and Android.
  EXPECT_EQ("-K", PopFront(args));

  // Specify the maximum number of file descriptors the process can open.
  EXPECT_EQ("-R", PopFront(args));
  EXPECT_EQ("RLIMIT_NOFILE,262144,262144", PopFront(args));

  // Finally, specify mount-passthrough command line arguments.
  EXPECT_EQ("--", PopFront(args));
  EXPECT_EQ("/usr/bin/mount-passthrough", PopFront(args));
  EXPECT_EQ(
      "--source=/home/user/2d6fef33bb331bb08f3ca9d4db7078d776a251a6/MyFiles",
      PopFront(args));
  EXPECT_EQ("--dest=/run/arcvm/media/MyFiles", PopFront(args));
  EXPECT_EQ("--fuse_umask=007", PopFront(args));
  EXPECT_EQ("--fuse_uid=10058", PopFront(args));
  EXPECT_EQ("--fuse_gid=1077", PopFront(args));
  EXPECT_EQ("--android_app_access_type=full", PopFront(args));
  EXPECT_EQ("--media_provider_uid=10058", PopFront(args));

  EXPECT_TRUE(args.empty());
}

// Container behaves very differently from VM (ex. not using the concierge
// namespace).
TEST_F(MountPassthroughUtilTest, ContainerMyFiles) {
  // From arc/container/myfiles/arc-myfiles.conf.
  const char* argv[] = {
      "mount-passthrough-jailed",
      "--source=/home/chronos/user/MyFiles",
      "--dest=/run/arc/media/MyFiles",
      "--fuse_umask=007",
      "--fuse_uid=1023",
      "--fuse_gid=1023",
  };

  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  auto args = CreateMinijailCommandLineArgs(flags);

  EXPECT_EQ("/sbin/minijail0", PopFront(args));

  // Use minimalistic-mountns profile.
  EXPECT_EQ("--profile=minimalistic-mountns", PopFront(args));
  EXPECT_EQ("--no-fs-restrictions", PopFront(args));

  // Same with VM.
  EXPECT_EQ("-N", PopFront(args));
  EXPECT_EQ("--uts", PopFront(args));
  EXPECT_EQ("-v", PopFront(args));
  EXPECT_EQ("-r", PopFront(args));
  EXPECT_EQ("-e", PopFront(args));
  EXPECT_EQ("-l", PopFront(args));
  EXPECT_EQ("-c", PopFront(args));
  EXPECT_EQ("cap_sys_admin+eip", PopFront(args));
  EXPECT_EQ("-u", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-g", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-G", PopFront(args));
  EXPECT_EQ("-K", PopFront(args));
  EXPECT_EQ("-R", PopFront(args));
  EXPECT_EQ("RLIMIT_NOFILE,8192,8192", PopFront(args));

  // Mount tmpfs on /mnt.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("tmpfs,/mnt,tmpfs,MS_NOSUID|MS_NODEV|MS_NOEXEC", PopFront(args));

  // Bind /dev/fuse to mount FUSE file systems.
  EXPECT_EQ("-b", PopFront(args));
  EXPECT_EQ("/dev/fuse", PopFront(args));

  // Mark PRIVATE recursively under (pivot) root, in order not to
  // expose shared mount points accidentally.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("none,/,none,0x44000", PopFront(args));

  // Mount source/dest directories.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x5000",
            PopFront(args));
  // 0x84000 = slave,rec
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x84000",
            PopFront(args));
  // 0x102e = bind,remount,noexec,nodev,nosuid
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x102e",
            PopFront(args));
  // 0x1000 = bind
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/MyFiles,/mnt/dest,none,0x1000", PopFront(args));
  // 0x102e = bind,remount,noexec,nodev,nosuid
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/MyFiles,/mnt/dest,none,0x102e", PopFront(args));

  // Mostly same with VM (different source/dest/uid/gid).
  EXPECT_EQ("--", PopFront(args));
  EXPECT_EQ("/usr/bin/mount-passthrough", PopFront(args));
  EXPECT_EQ("--source=/mnt/source", PopFront(args));
  EXPECT_EQ("--dest=/mnt/dest", PopFront(args));
  EXPECT_EQ("--fuse_umask=007", PopFront(args));
  EXPECT_EQ("--fuse_uid=1023", PopFront(args));
  EXPECT_EQ("--fuse_gid=1023", PopFront(args));
  EXPECT_EQ("--android_app_access_type=full", PopFront(args));

  EXPECT_TRUE(args.empty());
}

// This is very similar to ContainerMyFiles but --dest and
// --android_app_access_type are different. Make sure non-default
// --android_app_access_type value is handled correctly.
//
// MyFiles-write and MyFiles-default aren't tested as those are similar
// enough to ContainerMyFiles and ContainerMyFilesRead.
TEST_F(MountPassthroughUtilTest, ContainerMyFilesRead) {
  // From arc/container/myfiles/arc-myfiles-read.conf.
  const char* argv[] = {
      "mount-passthrough-jailed",
      "--source=/home/chronos/user/MyFiles",
      "--dest=/run/arc/media/MyFiles-read",
      "--fuse_umask=027",
      "--fuse_uid=0",
      "--fuse_gid=9997",
      "--android_app_access_type=read",
  };

  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  auto args = CreateMinijailCommandLineArgs(flags);

  // Same with ContainerMyFiles.
  EXPECT_EQ("/sbin/minijail0", PopFront(args));
  EXPECT_EQ("--profile=minimalistic-mountns", PopFront(args));
  EXPECT_EQ("--no-fs-restrictions", PopFront(args));
  EXPECT_EQ("-N", PopFront(args));
  EXPECT_EQ("--uts", PopFront(args));
  EXPECT_EQ("-v", PopFront(args));
  EXPECT_EQ("-r", PopFront(args));
  EXPECT_EQ("-e", PopFront(args));
  EXPECT_EQ("-l", PopFront(args));
  EXPECT_EQ("-c", PopFront(args));
  EXPECT_EQ("cap_sys_admin+eip", PopFront(args));
  EXPECT_EQ("-u", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-g", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-G", PopFront(args));
  EXPECT_EQ("-K", PopFront(args));
  EXPECT_EQ("-R", PopFront(args));
  EXPECT_EQ("RLIMIT_NOFILE,8192,8192", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("tmpfs,/mnt,tmpfs,MS_NOSUID|MS_NODEV|MS_NOEXEC", PopFront(args));
  EXPECT_EQ("-b", PopFront(args));
  EXPECT_EQ("/dev/fuse", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("none,/,none,0x44000", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x5000",
            PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x84000",
            PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/home/chronos/user/MyFiles,/mnt/source,none,0x102e",
            PopFront(args));

  // MyFiles-read should be used as the destination.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/MyFiles-read,/mnt/dest,none,0x1000",
            PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/MyFiles-read,/mnt/dest,none,0x102e",
            PopFront(args));

  // Same with ContainerMyFiles.
  EXPECT_EQ("--", PopFront(args));
  EXPECT_EQ("/usr/bin/mount-passthrough", PopFront(args));
  EXPECT_EQ("--source=/mnt/source", PopFront(args));
  EXPECT_EQ("--dest=/mnt/dest", PopFront(args));
  EXPECT_EQ("--fuse_umask=027", PopFront(args));
  EXPECT_EQ("--fuse_uid=0", PopFront(args));
  EXPECT_EQ("--fuse_gid=9997", PopFront(args));

  // The access type should be "read" instead of "full".
  EXPECT_EQ("--android_app_access_type=read", PopFront(args));

  EXPECT_TRUE(args.empty());
}

// On Container, /media/removable uses --use_default_selinux_context. Make
// sure that the flag is handled correctly.
// /media/removable-{write,default} aren't tested as those are similar
// enough to /media/removable-read.
TEST_F(MountPassthroughUtilTest, ContainerRemovableRead) {
  // From arc/container/removable-media/arc-removable-media-read.conf.
  const char* argv[] = {"mount-passthrough-jailed",
                        "--source=/media/removable",
                        "--dest=/run/arc/media/removable-read",
                        "--fuse_umask=027",
                        "--fuse_uid=0",
                        "--fuse_gid=9997",
                        "--android_app_access_type=read",
                        "--use_default_selinux_context"};

  base::CommandLine command_line(std::size(argv), argv);
  brillo::FlagHelper::GetInstance()->set_command_line_for_testing(
      &command_line);
  CommandLineFlags flags;
  ParseCommandLine(std::size(argv), argv, &flags);
  auto args = CreateMinijailCommandLineArgs(flags);

  // Same with ContainerMyFiles.
  EXPECT_EQ("/sbin/minijail0", PopFront(args));
  EXPECT_EQ("--profile=minimalistic-mountns", PopFront(args));
  EXPECT_EQ("--no-fs-restrictions", PopFront(args));
  EXPECT_EQ("-N", PopFront(args));
  EXPECT_EQ("--uts", PopFront(args));
  EXPECT_EQ("-v", PopFront(args));
  EXPECT_EQ("-r", PopFront(args));
  EXPECT_EQ("-e", PopFront(args));
  EXPECT_EQ("-l", PopFront(args));
  EXPECT_EQ("-c", PopFront(args));
  EXPECT_EQ("cap_sys_admin+eip", PopFront(args));
  EXPECT_EQ("-u", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-g", PopFront(args));
  EXPECT_EQ("chronos", PopFront(args));
  EXPECT_EQ("-G", PopFront(args));
  EXPECT_EQ("-K", PopFront(args));
  EXPECT_EQ("-R", PopFront(args));
  EXPECT_EQ("RLIMIT_NOFILE,8192,8192", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("tmpfs,/mnt,tmpfs,MS_NOSUID|MS_NODEV|MS_NOEXEC", PopFront(args));
  EXPECT_EQ("-b", PopFront(args));
  EXPECT_EQ("/dev/fuse", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("none,/,none,0x44000", PopFront(args));

  // /media/removable should be used as the source.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/media/removable,/mnt/source,none,0x5000", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/media/removable,/mnt/source,none,0x84000", PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/media/removable,/mnt/source,none,0x102e", PopFront(args));

  // /media/removable-read should be used as the destination.
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/removable-read,/mnt/dest,none,0x1000",
            PopFront(args));
  EXPECT_EQ("-k", PopFront(args));
  EXPECT_EQ("/run/arc/media/removable-read,/mnt/dest,none,0x102e",
            PopFront(args));

  // Same with ContainerMyFilesRead.
  EXPECT_EQ("--", PopFront(args));
  EXPECT_EQ("/usr/bin/mount-passthrough", PopFront(args));
  EXPECT_EQ("--source=/mnt/source", PopFront(args));
  EXPECT_EQ("--dest=/mnt/dest", PopFront(args));
  EXPECT_EQ("--fuse_umask=027", PopFront(args));
  EXPECT_EQ("--fuse_uid=0", PopFront(args));
  EXPECT_EQ("--fuse_gid=9997", PopFront(args));
  EXPECT_EQ("--android_app_access_type=read", PopFront(args));

  // The default SELinux context should be used.
  EXPECT_EQ("--use_default_selinux_context", PopFront(args));

  EXPECT_TRUE(args.empty());
}

}  // namespace arc
