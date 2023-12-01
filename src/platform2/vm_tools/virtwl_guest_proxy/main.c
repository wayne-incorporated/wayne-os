// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <linux/virtwl.h>

// This limits the number of child processes, which limits the number of
// concurrent connections to the proxy. This roughly corresponds to the number
// of concurrent wayland applications that can be running per machine.
#define MAX_CHILD_COUNT 128

// No matter what kind of virtwl fd we are given, a zero-sized ioctl send should
// succeed. This property is used to determine if the given fd is a virtwl fd.
static bool is_virtwl_fd(int fd) {
  struct virtwl_ioctl_txn ioctl_send;
  for (int fd_idx = 0; fd_idx < VIRTWL_SEND_MAX_ALLOCS; fd_idx++)
    ioctl_send.fds[fd_idx] = -1;
  ioctl_send.len = 0;
  return ioctl(fd, VIRTWL_IOCTL_SEND, &ioctl_send) == 0;
}

static void* pipe_proxy_routine(void* args) {
  int* fds = (int*)args;
  int in_pipe = fds[0];
  int out_pipe = fds[1];
  free(fds);

  uint8_t buf[PIPE_BUF];
  for (;;) {
    int ret = read(in_pipe, buf, sizeof(buf));
    if (ret == -1) {
      syslog(LOG_USER | LOG_ERR, "error reading from input pipe: %m");
      break;
    }

    // Check for hangup.
    if (ret == 0)
      break;

    size_t count = ret;
    ret = write(out_pipe, buf, count);
    if (ret == -1) {
      syslog(LOG_USER | LOG_ERR, "error writing to output pipe: %m");
      break;
    }

    // Check for hangup
    if (ret != count) {
      syslog(LOG_USER | LOG_ERR, "incomplete write to output pipe %d",
             out_pipe);
      break;
    }
  }

  close(in_pipe);
  close(out_pipe);
  return NULL;
}

static int launch_pipe_proxy(int in_fd, int out_fd) {
  int* fds = calloc(2, sizeof(int));
  if (!fds)
    return ENOMEM;

  fds[0] = in_fd;
  fds[1] = out_fd;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t thread;
  int ret = pthread_create(&thread, &attr, pipe_proxy_routine, fds);
  if (ret) {
    free(fds);
    syslog(LOG_USER | LOG_DEBUG, "failed to create pipe proxy thread: %m");
    return ret;
  }

  return 0;
}

static int handle_server_in(int wl0_fd, int server_fd, int client_fd) {
  uint8_t ioctl_buf[4096];
  struct virtwl_ioctl_txn* ioctl_recv = (struct virtwl_ioctl_txn*)ioctl_buf;
  void* recv_data = ioctl_buf + sizeof(struct virtwl_ioctl_txn);
  size_t max_recv_size = sizeof(ioctl_buf) - sizeof(struct virtwl_ioctl_txn);
  char fd_buf[CMSG_LEN(sizeof(int) * VIRTWL_SEND_MAX_ALLOCS)];

  ioctl_recv->len = max_recv_size;
  int ret = ioctl(server_fd, VIRTWL_IOCTL_RECV, ioctl_recv);
  if (ret) {
    syslog(LOG_USER | LOG_DEBUG, "wayland server socket has hungup: %m");
    return -1;
  }

  struct iovec buffer_iov;
  buffer_iov.iov_base = recv_data;
  buffer_iov.iov_len = ioctl_recv->len;

  struct msghdr msg = {0};
  msg.msg_iov = &buffer_iov;
  msg.msg_iovlen = 1;
  msg.msg_control = fd_buf;

  // Simply counts how manye FDs the kernel gave us.
  int fd_count;
  for (fd_count = 0; fd_count < VIRTWL_SEND_MAX_ALLOCS; fd_count++) {
    if (ioctl_recv->fds[fd_count] < 0)
      break;
  }

  if (fd_count > 0) {
    // Need to set msg_controllen so CMSG_FIRSTHDR will return the first
    // cmsghdr. We copy every fd we just received from the ioctl into this
    // cmsghdr.
    msg.msg_controllen = sizeof(fd_buf);
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
    memcpy(CMSG_DATA(cmsg), ioctl_recv->fds, fd_count * sizeof(int));
    msg.msg_controllen = cmsg->cmsg_len;
  }

  ssize_t write_size = sendmsg(client_fd, &msg, MSG_NOSIGNAL);

  int i;
  for (i = 0; i < fd_count; i++)
    close(ioctl_recv->fds[i]);

  if (write_size != ioctl_recv->len) {
    syslog(LOG_USER | LOG_ERR, "failed sendmsg to client: %m");
    return -1;
  }

  return 0;
}

static int handle_client_in(int wl0_fd, int server_fd, int client_fd) {
  uint8_t ioctl_buf[4096];
  struct virtwl_ioctl_txn* ioctl_send = (struct virtwl_ioctl_txn*)ioctl_buf;
  void* send_data = ioctl_buf + sizeof(struct virtwl_ioctl_txn);
  size_t max_send_size = sizeof(ioctl_buf) - sizeof(struct virtwl_ioctl_txn);
  char fd_buf[CMSG_LEN(sizeof(int) * VIRTWL_SEND_MAX_ALLOCS)];
  uint8_t retain_fds[VIRTWL_SEND_MAX_ALLOCS] = {0};

  struct iovec buffer_iov;
  buffer_iov.iov_base = send_data;
  buffer_iov.iov_len = max_send_size;

  struct msghdr msg = {0};
  msg.msg_iov = &buffer_iov;
  msg.msg_iovlen = 1;
  msg.msg_control = fd_buf;
  msg.msg_controllen = sizeof(fd_buf);

  ssize_t read_size = recvmsg(client_fd, &msg, 0);
  if (read_size == 0) {
    syslog(LOG_USER | LOG_DEBUG, "client has hungup");
    return -1;
  }

  if (read_size < 0) {
    syslog(LOG_USER | LOG_ERR, "failed recvmsg from client: %m");
    return -1;
  }

  for (int fd_idx = 0; fd_idx < VIRTWL_SEND_MAX_ALLOCS; fd_idx++)
    ioctl_send->fds[fd_idx] = -1;

  // If there were any FDs recv'd by recvmsg, there will be some data in the
  // msg_control buffer. To get the FDs out we iterate all cmsghdr's within and
  // unpack the FDs if the cmsghdr type is SCM_RIGHTS.
  struct cmsghdr* cmsg = msg.msg_controllen != 0 ? CMSG_FIRSTHDR(&msg) : NULL;
  for (int fd_idx = 0; cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
      continue;

    size_t cmsg_fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    // fd_idx will never exceed VIRTWL_SEND_MAX_ALLOCS because the
    // control message buffer only allocates enough space for that many FDs.
    memcpy(&ioctl_send->fds[fd_idx], CMSG_DATA(cmsg),
           cmsg_fd_count * sizeof(int));
    fd_idx += cmsg_fd_count;
  }

  for (int fd_idx = 0; fd_idx < VIRTWL_SEND_MAX_ALLOCS; fd_idx++) {
    int fd = ioctl_send->fds[fd_idx];
    if (fd < 0)
      break;
    if (is_virtwl_fd(fd))
      continue;

    // If the client sends us a non-virtwl FD, it's likely some kind of pipe
    // that we can manually proxy in another thread.
    struct virtwl_ioctl_new new_pipe = {
        .type = 0,
        .fd = -1,
        .flags = 0,
        .size = 0,
    };

    int flags = fcntl(fd, F_GETFL) & O_ACCMODE;
    switch (flags) {
      case O_RDONLY:
        new_pipe.type = VIRTWL_IOCTL_NEW_PIPE_WRITE;
        break;
      case O_WRONLY:
      // virtwl does not support read/write pipes but pipes sent from the client
      // are likely intended to be written to by the remote end.
      case O_RDWR:
        new_pipe.type = VIRTWL_IOCTL_NEW_PIPE_READ;
        break;
      default:
        continue;
    }

    int ret = ioctl(wl0_fd, VIRTWL_IOCTL_NEW, &new_pipe);
    if (ret) {
      syslog(LOG_USER | LOG_ERR, "failed to create virtwl pipe: %m");
      return -1;
    }

    if (flags == O_RDONLY)
      ret = launch_pipe_proxy(fd, new_pipe.fd);
    else
      ret = launch_pipe_proxy(new_pipe.fd, fd);

    if (ret) {
      close(new_pipe.fd);
      return -1;
    } else {
      ioctl_send->fds[fd_idx] = new_pipe.fd;
      retain_fds[fd_idx] = 1;
    }
  }

  // The FDs and data were extracted from the recvmsg call into the ioctl_send
  // structure which we now pass along to the kernel.
  ioctl_send->len = read_size;
  int ret = ioctl(server_fd, VIRTWL_IOCTL_SEND, ioctl_send);
  if (ret)
    syslog(LOG_USER | LOG_ERR, "failed to IOCTL_SEND to server: %m");

  for (int fd_idx = 0; fd_idx < VIRTWL_SEND_MAX_ALLOCS; fd_idx++) {
    int fd = ioctl_send->fds[fd_idx];
    if (fd >= 0 && !retain_fds[fd_idx])
      close(fd);
  }

  if (ret)
    return -1;

  return 0;
}

static int proxy_main(int wl0_fd, int wl_fd, int client_socket) {
  int (*handlers[2])(int, int, int) = {handle_client_in, handle_server_in};
  struct pollfd fds[2];

  fds[0].fd = client_socket;
  fds[0].events = POLLIN;
  fds[1].fd = wl_fd;
  fds[1].events = POLLIN;

  int ret = 0;
  while ((ret = poll(fds, 2, -1)) != -1) {
    for (int i = 0; i < 2; i++) {
      if ((fds[i].revents & POLLIN) == 0) {
        if ((fds[i].revents & POLLHUP) == 0)
          continue;
        else
          goto end;
      }

      ret = handlers[i](wl0_fd, wl_fd, client_socket);
      if (ret)
        goto end;
    }
  }

end:
  close(wl0_fd);
  close(wl_fd);
  close(client_socket);

  return ret;
}

static void empty_handler(int signum) {}

int main(int argc, char** argv) {
  // Handle broken pipes without signals that kill the entire process.
  signal(SIGPIPE, SIG_IGN);

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s/wayland-0",
           getenv("XDG_RUNTIME_DIR"));
  socklen_t len = strlen(addr.sun_path) + sizeof(addr.sun_family);

  unlink(addr.sun_path);
  // The socket must be world-writable to be accessible by a container with
  // user namespaces.
  umask(0);
  int server_socket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server_socket < 0) {
    syslog(LOG_USER | LOG_ERR, "failed to create listening socket: %m");
    return 1;
  }
  if (bind(server_socket, (struct sockaddr*)&addr, len) != 0) {
    syslog(LOG_USER | LOG_ERR, "failed to bind listening socket: %m");
    return 1;
  }
  if (listen(server_socket, 8) != 0) {
    syslog(LOG_USER | LOG_ERR, "failed to listen to socket: %m");
    return 1;
  }

  struct sigaction child_action;
  memset(&child_action, 0, sizeof(child_action));
  sigemptyset(&child_action.sa_mask);
  child_action.sa_handler = empty_handler;
  sigaction(SIGCHLD, &child_action, NULL);

  int child_count = 0;
  for (;;) {
    // The child_count is used to limit the number of child processes that one
    // proxy will handle before it will start dropping new connections. Because
    // accept is the only blocking call made in the main loop, we can reap
    // children and update the child_count just before to get an accurate count.
    // If children die while blocked in accept, the empty signal handler will
    // ensure the accept gets interrupted, which we check for in order to
    // restart the main loop. There is an intrinsic race condition in which a
    // child dies just after accept returns a new connection in which case
    // child_count would be inaccurate and lead to an inappropriate drop of the
    // new connection. However, this race condition is unavoidable and will not
    // lead to a permanent DoS as the child_count will become accurate on the
    // next iteration.
    while (waitpid(-1, NULL, WNOHANG) > 0) {
      if (child_count > 0) {
        child_count--;
      } else {
        syslog(LOG_USER | LOG_WARNING, "reaped more children than spawned");
      }
    }

    struct sockaddr_un remote_addr;
    socklen_t remote_addr_len = sizeof(struct sockaddr_un);
    int client_socket =
        accept(server_socket, (struct sockaddr*)&remote_addr, &remote_addr_len);
    if (client_socket == -1) {
      // An EINTR probably means that the SIGCHLD handler was called and
      // children need to be reaped.
      if (errno == EINTR)
        continue;
      syslog(LOG_USER | LOG_ERR, "failed to accept incoming socket: %m");
      return 1;
    }
    if (child_count >= MAX_CHILD_COUNT) {
      syslog(LOG_USER | LOG_WARNING,
             "dropping excessive number of client connections");
      close(client_socket);
      continue;
    }

    static char log_ident[32] = "virtwl";
    struct sockaddr_storage peer_name;
    socklen_t peer_name_len = sizeof(struct sockaddr_storage);
    int ret = getsockname(client_socket, (struct sockaddr*)&peer_name,
                          &peer_name_len);
    if (ret == 0) {
      struct sockaddr_un* peer_name_un = (struct sockaddr_un*)&peer_name;
      syslog(LOG_USER | LOG_INFO, "client connected: %s",
             peer_name_un->sun_path);
      snprintf(log_ident, sizeof(log_ident) - 1, "virtwl-%s",
               peer_name_un->sun_path);
    } else {
      syslog(LOG_USER | LOG_INFO, "client connected: error getting name: %m");
    }

    // We use fork here so that each client connection is isolated from crashes
    // in the other, and so that each gets it's own set of FDs.
    ret = fork();
    if (ret == 0) { /* child */
      openlog(log_ident, LOG_PERROR | LOG_PID, LOG_USER);
      close(server_socket);
      int wl_fd = open("/dev/wl0", O_RDWR | O_CLOEXEC);
      if (wl_fd < 0) {
        syslog(LOG_USER | LOG_ERR, "failed to open wl0: %m");
        return 1;
      }

      struct virtwl_ioctl_new new_ctx = {
          .type = VIRTWL_IOCTL_NEW_CTX,
          .fd = -1,
          .flags = 0,
          .size = 0,
      };

      ret = ioctl(wl_fd, VIRTWL_IOCTL_NEW, &new_ctx);
      if (ret) {
        syslog(LOG_USER | LOG_ERR, "failed to create new wayland context: %m");
        return 1;
      }

      return proxy_main(wl_fd, new_ctx.fd, client_socket);
    } else if (ret == -1) {
      syslog(LOG_USER | LOG_ERR, "failed to fork client handler: %m");
    }

    child_count++;
    close(client_socket);
  }
}
