// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/http_server/server.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <iomanip>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "p2p/common/clock.h"
#include "p2p/common/server_message.h"
#include "p2p/common/struct_serializer.h"
#include "p2p/http_server/connection_delegate_interface.h"

using std::string;

using base::FilePath;

using p2p::util::P2PServerMessage;
using p2p::util::P2PServerMessageType;

namespace p2p {

namespace http_server {

Server::Server(const FilePath& directory,
               uint16_t port,
               int message_fd,
               ConnectionDelegateFactory delegate_factory)
    : thread_pool_("p2p-http-server", 10),
      directory_(directory),
      dirfd_(-1),
      port_(port),
      message_fd_(message_fd),
      max_download_rate_(0),
      started_(false),
      listen_fd_(-1),
      listen_source_id_(0),
      num_connections_(0),
      delegate_factory_(delegate_factory) {
  clock_.reset(new p2p::common::Clock);
}

Server::~Server() {
  CHECK(!started_);
}

/* ------------------------------------------------------------------------ */

void Server::Stop() {
  CHECK(started_);

  LOG(INFO) << "Stopping server";

  if (dirfd_ != -1) {
    if (close(dirfd_) != 0) {
      PLOG(ERROR) << "Error closing directory";
    }
  }
  dirfd_ = -1;

  if (listen_fd_ != -1) {
    if (close(listen_fd_) != 0) {
      PLOG(ERROR) << "Error closing listening socket";
    }
    listen_fd_ = -1;
  }

  if (listen_source_id_ != 0) {
    if (!g_source_remove(listen_source_id_)) {
      LOG(ERROR) << "Error removing GSource for listening socket";
    }
    listen_source_id_ = 0;
  }

  LOG(INFO) << "Waiting for all connection delegates";

  thread_pool_.JoinAll();

  LOG(INFO) << "Stopped server";

  started_ = false;
}

bool Server::Start() {
  struct ::sockaddr_in6 sock_addr;

  CHECK(!started_);
  started_ = true;

  thread_pool_.Start();

  dirfd_ = open(directory_.value().c_str(), O_DIRECTORY);
  if (dirfd_ == -1) {
    PLOG(ERROR) << "Error opening directory";
    Stop();
    return false;
  }

  listen_fd_ =
      socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
  if (listen_fd_ == -1) {
    PLOG(ERROR) << "Cannot create socket";
    Stop();
    return false;
  }

  memset(&sock_addr, 0, sizeof sock_addr);

  sock_addr.sin6_family = AF_INET6;
  sock_addr.sin6_port = htons(port_);

  int optval = 1;
  if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &optval,
                 sizeof optval) == -1) {
    PLOG(ERROR) << "setsockopt failed";
    Stop();
    return false;
  }

  if (bind(listen_fd_, reinterpret_cast<const struct ::sockaddr*>(&sock_addr),
           sizeof sock_addr) == -1) {
    PLOG(ERROR) << "bind failed";
    Stop();
    return false;
  }

  if (listen(listen_fd_, 10) == -1) {
    PLOG(ERROR) << "listen failed";
    Stop();
    return false;
  }

  // Figure out port number if we asked bind(2) for a random one
  if (port_ == 0) {
    struct ::sockaddr_in bound_addr = {0};
    socklen_t bound_addr_len = sizeof bound_addr;
    if (getsockname(listen_fd_,
                    reinterpret_cast<struct ::sockaddr*>(&bound_addr),
                    &bound_addr_len) != 0) {
      PLOG(ERROR) << "getsockname failed";
      Stop();
      return false;
    }
    port_ = ntohs(bound_addr.sin_port);
  }

  VLOG(1) << "listening on port " << port_;

  GIOChannel* io_channel = g_io_channel_unix_new(listen_fd_);
  listen_source_id_ = g_io_add_watch(
      io_channel,
      static_cast<GIOCondition>(G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP),
      OnIOChannelActivity, this);
  CHECK_NE(0U, listen_source_id_);
  g_io_channel_unref(io_channel);

  // Report the port number back to the p2p-server once we are accepting
  // connections on that port.
  ReportServerMessage(p2p::util::kP2PServerPortNumber, port_);

  return true;
}

void Server::SetMaxDownloadRate(int64_t bytes_per_sec) {
  max_download_rate_ = bytes_per_sec;
}

uint16_t Server::Port() {
  return port_;
}

int Server::NumConnections() {
  return num_connections_;
}

p2p::common::ClockInterface* Server::Clock() {
  return clock_.get();
}

// Returns a string with |addr| in a human-readable format.
static string PrintAddress(struct ::sockaddr* addr, socklen_t addr_len) {
  char buf[256];
  string ret;

  CHECK(addr != NULL);

  switch (addr->sa_family) {
    case AF_INET: {
      struct ::sockaddr_in* addr_in =
          reinterpret_cast<struct ::sockaddr_in*>(addr);
      if (inet_ntop(AF_INET, &addr_in->sin_addr, buf, sizeof buf) == NULL) {
        PLOG(ERROR) << "Error printing address";
      } else {
        ret = string(buf);
      }
    } break;

    case AF_INET6: {
      struct ::sockaddr_in6* addr_in6 =
          reinterpret_cast<struct ::sockaddr_in6*>(addr);

      // Note that inet_ntop(3) doesn't handle IPv4-mapped IPv6
      // addresses [1] the way you'd expect .. for example, it returns
      // "::ffff:172.22.72.163" instead of the more traditional IPv4
      // notation "172.22.72.163". Fortunately, this is pretty easy to
      // fix ourselves.
      //
      // [1] : see RFC 4291, section 2.5.5.2 for what that means
      //       http://tools.ietf.org/html/rfc4291#section-2.5.5
      //
      uint32_t* dwords = reinterpret_cast<uint32_t*>(&addr_in6->sin6_addr);
      if (dwords[0] == 0x00000000 && dwords[1] == 0x00000000 &&
          dwords[2] == htonl(0x0000ffff)) {
        uint8_t* bytes = reinterpret_cast<uint8_t*>(&addr_in6->sin6_addr);
        snprintf(buf, sizeof buf, "%d.%d.%d.%d", bytes[12], bytes[13],
                 bytes[14], bytes[15]);
        ret = string(buf);
      } else {
        if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, buf, sizeof buf) ==
            NULL) {
          PLOG(ERROR) << "Error printing address";
        } else {
          ret = string(buf);
        }
      }
    } break;

    default:
      LOG(ERROR) << "No support for printing socket address with family "
                 << addr->sa_family;
      break;
  }
  return ret;
}

void Server::ReportServerMessage(P2PServerMessageType msg_type, int64_t value) {
  P2PServerMessage msg = (P2PServerMessage){.magic = p2p::util::kP2PServerMagic,
                                            .message_type = msg_type,
                                            .value = value};
  LOG(INFO) << "Sending message " << ToString(msg);
  lock_.Acquire();
  p2p::util::StructSerializerWrite<P2PServerMessage>(message_fd_, msg);
  lock_.Release();
}

void Server::UpdateNumConnections(int delta_num_connections) {
  lock_.Acquire();
  num_connections_ += delta_num_connections;
  int num_connections = num_connections_;
  lock_.Release();
  ReportServerMessage(p2p::util::kP2PServerNumConnections, num_connections);
}

void Server::ConnectionTerminated(ConnectionDelegateInterface* delegate) {
  UpdateNumConnections(-1);
}

gboolean Server::OnIOChannelActivity(GIOChannel* source,
                                     GIOCondition condition,
                                     gpointer user_data) {
  Server* server = reinterpret_cast<Server*>(user_data);
  struct ::sockaddr_in6 addr_in6 = {0};
  struct ::sockaddr* addr = reinterpret_cast<struct ::sockaddr*>(&addr_in6);
  socklen_t addr_len = sizeof addr_in6;
  int fd = -1;

  VLOG(1) << "Condition " << condition << " on listening socket";

  fd = accept(server->listen_fd_, addr, &addr_len);
  if (fd == -1) {
    PLOG(ERROR) << "accept failed";
  } else {
    ConnectionDelegateInterface* delegate = server->delegate_factory_(
        server->dirfd_, fd, PrintAddress(addr, addr_len), server,
        server->max_download_rate_);
    server->UpdateNumConnections(1);

    // Report P2P.Server.ClientCount every time a client connects.
    server->ReportServerMessage(p2p::util::kP2PServerClientCount,
                                server->num_connections_);

    server->thread_pool_.AddWork(delegate);
  }

  return TRUE;  // keep source around
}

}  // namespace http_server

}  // namespace p2p
