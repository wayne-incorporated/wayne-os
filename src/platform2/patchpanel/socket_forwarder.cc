// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/socket_forwarder.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/task/bind_post_task.h>
#include <base/time/time.h>

namespace patchpanel {
namespace {
constexpr int kWaitTimeoutMs = 1000;
// Maximum number of epoll events to process per wait.
constexpr int kMaxEvents = 4;

std::ostream& operator<<(std::ostream& stream,
                         const struct epoll_event& event) {
  stream << "{ fd: " << event.data.fd << ", events: 0x" << std::hex
         << event.events << "}";
  return stream;
}

bool SetPollEvents(Socket* socket, int cfd, uint32_t events) {
  struct epoll_event ev;
  ev.events = events;
  ev.data.fd = socket->fd();
  if (epoll_ctl(cfd, EPOLL_CTL_MOD, socket->fd(), &ev) == -1) {
    PLOG(ERROR) << "epoll_ctl(" << ev << ") failed";
    return false;
  }
  return true;
}

}  // namespace

SocketForwarder::SocketForwarder(const std::string& name,
                                 std::unique_ptr<Socket> sock0,
                                 std::unique_ptr<Socket> sock1)
    : base::SimpleThread(name),
      sock0_(std::move(sock0)),
      sock1_(std::move(sock1)),
      len0_(0),
      len1_(0),
      eof_(-1),
      poll_(false),
      done_(false) {
  DCHECK(sock0_);
  DCHECK(sock1_);
}

SocketForwarder::~SocketForwarder() {
  // Ensure the polling loop exits.
  poll_ = false;
  Join();
}

bool SocketForwarder::IsRunning() const {
  return !done_;
}

void SocketForwarder::SetStopQuitClosureForTesting(base::OnceClosure closure) {
  stop_quit_closure_for_testing_ =
      BindPostTaskToCurrentDefault(std::move(closure));
}

void SocketForwarder::Run() {
  LOG(INFO) << "Starting forwarder: " << *sock0_ << " <-> " << *sock1_;

  // We need these sockets to be non-blocking.
  if (fcntl(sock0_->fd(), F_SETFL,
            fcntl(sock0_->fd(), F_GETFL, 0) | O_NONBLOCK) < 0 ||
      fcntl(sock1_->fd(), F_SETFL,
            fcntl(sock1_->fd(), F_GETFL, 0) | O_NONBLOCK) < 0) {
    PLOG(ERROR) << "fcntl failed";
    if (stop_quit_closure_for_testing_)
      std::move(stop_quit_closure_for_testing_).Run();
    return;
  }

  Poll();

  LOG(INFO) << "Forwarder stopped: " << *sock0_ << " <-> " << *sock1_;
  done_ = true;
  sock1_.reset();
  sock0_.reset();
  if (stop_quit_closure_for_testing_)
    std::move(stop_quit_closure_for_testing_).Run();
}

void SocketForwarder::Poll() {
  base::ScopedFD cfd(epoll_create1(0));
  if (!cfd.is_valid()) {
    PLOG(ERROR) << "epoll_create1 failed";
    return;
  }
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = sock0_->fd();
  if (epoll_ctl(cfd.get(), EPOLL_CTL_ADD, sock0_->fd(), &ev) == -1) {
    PLOG(ERROR) << "epoll_ctl failed";
    return;
  }
  ev.data.fd = sock1_->fd();
  if (epoll_ctl(cfd.get(), EPOLL_CTL_ADD, sock1_->fd(), &ev) == -1) {
    PLOG(ERROR) << "epoll_ctl failed";
    return;
  }

  poll_ = true;
  struct epoll_event events[kMaxEvents];
  while (poll_) {
    int n = epoll_wait(cfd.get(), events, kMaxEvents, kWaitTimeoutMs);
    if (n == -1) {
      if (errno == EINTR) {
        LOG(INFO) << "Resume epoll_wait from interruption.";
        continue;
      }
      PLOG(ERROR) << "epoll_wait failed";
      return;
    }
    for (int i = 0; i < n; ++i) {
      if (!poll_ ||
          !ProcessEvents(events[i].events, events[i].data.fd, cfd.get()))
        return;
    }
  }
}

bool SocketForwarder::ProcessEvents(uint32_t events, int efd, int cfd) {
  if (events & EPOLLERR) {
    int so_error;
    socklen_t optlen = sizeof(so_error);
    getsockopt(efd, SOL_SOCKET, SO_ERROR, &so_error, &optlen);
    PLOG(WARNING) << "Socket error: (" << so_error << ") " << *sock0_ << " <-> "
                  << *sock1_;
    return false;
  }

  if (events & EPOLLOUT) {
    Socket* dst;
    char* buf;
    size_t* len;
    if (sock0_->fd() == efd) {
      dst = sock0_.get();
      buf = buf1_;
      len = &len1_;
    } else {
      dst = sock1_.get();
      buf = buf0_;
      len = &len0_;
    }

    ssize_t r = dst->SendTo(buf, *len);
    if (r < 0) {
      PLOG(ERROR) << "Failed to send data to " << dst;
      return false;
    }
    size_t bytes = static_cast<size_t>(r);

    // Still unavailable.
    if (bytes == 0)
      return true;

    // Partial write.
    if (bytes < *len)
      memmove(&buf[0], &buf[bytes], *len - bytes);
    *len -= bytes;

    // If all the buffered data was written to the socket and the peer socket is
    // still open for writing, listen for read events on the socket.
    if (*len == 0 && eof_ != dst->fd() && !SetPollEvents(dst, cfd, EPOLLIN))
      return false;
  }

  Socket *src, *dst;
  char* buf;
  size_t* len;
  if (sock0_->fd() == efd) {
    src = sock0_.get();
    dst = sock1_.get();
    buf = buf0_;
    len = &len0_;
  } else {
    src = sock1_.get();
    dst = sock0_.get();
    buf = buf1_;
    len = &len1_;
  }

  // Skip the read if this buffer is still pending write: requires that
  // epoll_wait is in level-triggered mode.
  if (*len > 0)
    return true;

  if (events & EPOLLIN) {
    ssize_t r = src->RecvFrom(buf, kBufSize);
    if (r < 0) {
      PLOG(ERROR) << "Failed to receive data from " << src;
      return false;
    }
    *len = static_cast<size_t>(r);

    if (*len == 0)
      return HandleConnectionClosed(src, dst, cfd);

    r = dst->SendTo(buf, *len);
    if (r < 0) {
      PLOG(ERROR) << "Failed to send data to " << dst;
      return false;
    }
    size_t bytes = static_cast<size_t>(r);

    if (bytes > 0) {
      // Partial write.
      if (bytes < *len)
        memmove(&buf[0], &buf[bytes], *len - bytes);
      *len -= bytes;
    }

    if (*len > 0 && !SetPollEvents(dst, cfd, EPOLLOUT))
      return false;
  }

  if (events & EPOLLHUP) {
    LOG(INFO) << "Peer closed connection: " << *sock0_ << " <-> " << *sock1_;
    return false;
  }
  return true;
}

bool SocketForwarder::HandleConnectionClosed(Socket* src,
                                             Socket* dst,
                                             int cfd) {
  LOG(INFO) << "Peer closed connection: " << *src;
  if (eof_ == dst->fd()) {
    // Stop the forwarder since the other peer has already closed the
    // connection.
    LOG(INFO) << "Closed connection: " << *sock0_ << " <-> " << *sock1_;
    return false;
  }
  // Stop listening for read ready events from |src|.
  if (!SetPollEvents(src, cfd, 0))
    return false;

  // Propagate the shut down for writing to the other peer. This is safe
  // to do since reading the EOF on |src| only happens if the buffer
  // associated with the |src| socket if empty, so there's no outstanding
  // data to be written to |dst|.
  if (shutdown(dst->fd(), SHUT_WR) == -1) {
    PLOG(ERROR) << "Shutting down " << *socket << " for writing failed";
    return false;
  }

  eof_ = src->fd();
  return true;
}
}  // namespace patchpanel
