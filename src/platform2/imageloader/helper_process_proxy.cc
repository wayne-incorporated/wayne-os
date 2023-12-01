// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/helper_process_proxy.h"

#include <poll.h>
#include <signal.h>
#include <sys/socket.h>

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/launch.h>

#include "imageloader/component.h"
#include "imageloader/imageloader_impl.h"
#include "imageloader/ipc.pb.h"
#include "imageloader/verity_mounter.h"

namespace imageloader {

namespace {
// Use a timeout for polling that's greater than the DBus timeout in case the
// component/DLC to mount is very large.
constexpr int kPollingTimeoutSeconds = 60;
}  // namespace

void HelperProcessProxy::Start(int argc,
                               char* argv[],
                               const std::string& fd_arg) {
  int control[2];

  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, control) != 0)
    PLOG(FATAL) << "socketpair failed";

  control_fd_.reset(control[0]);
  const int subprocess_fd = control[1];

  CHECK_GE(argc, 1);
  std::vector<std::string> child_argv;
  for (int i = 0; i < argc; i++)
    child_argv.push_back(argv[i]);

  child_argv.push_back(fd_arg + "=" + std::to_string(subprocess_fd));

  base::FileHandleMappingVector fd_mapping;
  fd_mapping.push_back({subprocess_fd, subprocess_fd});

  base::LaunchOptions options;
  options.fds_to_remap = std::move(fd_mapping);

  base::Process p = base::LaunchProcess(child_argv, options);
  CHECK(p.IsValid());
  pid_ = p.Pid();
}

std::unique_ptr<CommandResponse> HelperProcessProxy::SendCommand(
    const ImageCommand& image_command, struct msghdr* msg) {
  std::vector<char> msg_buf(image_command.ByteSizeLong());
  if (!image_command.SerializeToArray(msg_buf.data(), msg_buf.size()))
    LOG(FATAL) << "error serializing protobuf";

  struct iovec iov[1];
  iov[0].iov_base = msg_buf.data();
  iov[0].iov_len = image_command.ByteSizeLong();

  msg->msg_iov = iov;
  msg->msg_iovlen = sizeof(iov) / sizeof(iov[0]);

  if (sendmsg(control_fd_.get(), msg, 0) < 0)
    PLOG(FATAL) << "sendmsg failed";

  return WaitForResponse();
}

bool HelperProcessProxy::SendMountCommand(int fd,
                                          const std::string& path,
                                          FileSystem fs_type,
                                          const std::string& table) {
  struct msghdr msg = {0};
  char fds[CMSG_SPACE(sizeof(fd))];
  memset(fds, '\0', sizeof(fds));

  // 1. Construct message object.
  ImageCommand image_command;
  image_command.mutable_mount_command()->set_mount_path(path);
  image_command.mutable_mount_command()->set_table(table);

  // Convert the internal enum to the protobuf enum.
  switch (fs_type) {
    case FileSystem::kExt4:
      image_command.mutable_mount_command()->set_fs_type(MountCommand::EXT4);
      break;
    case FileSystem::kSquashFS:
      image_command.mutable_mount_command()->set_fs_type(MountCommand::SQUASH);
      break;
    default:
      LOG(FATAL) << "Unknown file system type passed to helper process.";
  }

  // 2. Encode the fd into message.
  msg.msg_control = fds;
  msg.msg_controllen = sizeof(fds);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  // Move the file descriptor into the payload.
  memmove(CMSG_DATA(cmsg), &fd, sizeof(fd));
  msg.msg_controllen = cmsg->cmsg_len;

  // 3. Send the command.
  return SendCommand(image_command, &msg)->success();
}

bool HelperProcessProxy::SendUnmountAllCommand(
    bool dry_run,
    const std::string& rootpath,
    std::vector<std::string>* paths) {
  struct msghdr msg = {0};

  // 1. Construct message object.
  ImageCommand image_command;
  image_command.mutable_unmount_all_command()->set_dry_run(dry_run);
  image_command.mutable_unmount_all_command()->set_unmount_rootpath(rootpath);

  // 2. Send the command.
  std::unique_ptr<CommandResponse> response = SendCommand(image_command, &msg);

  // 3. Process return value.
  if (paths) {
    for (int i = 0; i < response->paths_size(); i++) {
      std::string path(response->paths(i));
      paths->push_back(path);
    }
  }
  return response->success();
}

bool HelperProcessProxy::SendUnmountCommand(const std::string& path) {
  struct msghdr msg = {0};

  // 1. Construct message object.
  ImageCommand image_command;
  image_command.mutable_unmount_command()->set_unmount_path(path);

  // 2. Send the command.
  return SendCommand(image_command, &msg)->success();
}

std::unique_ptr<CommandResponse> HelperProcessProxy::WaitForResponse() {
  struct pollfd pfd;
  pfd.fd = control_fd_.get();
  pfd.events = POLLIN;

  CHECK_LE(kDMSetupTimeoutSeconds, kPollingTimeoutSeconds);
  int rc = poll(&pfd, 1, kPollingTimeoutSeconds * 1000 /* (ms) */);
  PCHECK(rc >= 0 || errno == EINTR);

  std::unique_ptr<CommandResponse> response =
      std::make_unique<CommandResponse>();
  if (pfd.revents & POLLIN) {
    char buffer[4096];
    memset(buffer, '\0', sizeof(buffer));
    ssize_t bytes =
        HANDLE_EINTR(read(control_fd_.get(), buffer, sizeof(buffer)));
    PCHECK(bytes != -1);

    if (!response->ParseFromArray(buffer, bytes)) {
      LOG(FATAL) << "could not deserialize protobuf: " << buffer;
    }
  }

  return response;
}

}  // namespace imageloader
