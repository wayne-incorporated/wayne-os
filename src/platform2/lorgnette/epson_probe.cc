// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/epson_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include <map>
#include <string>
#include <unordered_set>

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/stl_util.h>
#include <chromeos/dbus/service_constants.h>

#include "lorgnette/firewall_manager.h"

namespace lorgnette {

namespace epson_probe {

namespace {

const uint16_t kEpsonProbePort = 3289;
const char kEpsonDeviceNamePrefix[] = "epson2:net:";
const int kSyscallSuccess = 0;
const char kScannerManufacturerEpson[] = "Epson";
const char kScannerModelNetwork[] = "Network";
const char kScannerTypeFlatbed[] = "flatbed scanner";
const char kProbePacket[] = "EPSONP\0\xff\0\0\0\0\0\0\0";
const char kReplyPrefix[] = "EPSON";
const int kExpectedReplySize = 76;
const int kReplyWaitTimeSeconds = 1;

static_assert(sizeof(kReplyPrefix) < kExpectedReplySize,
              "Reply prefix should be smaller than the expected reply size");

}  // namespace

static bool GetTimeMonotonic(struct timeval* tv) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return false;
  }

  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec / 1000;
  return true;
}

static bool CreateBroadcastSocket(int* broadcast_socket, uint16_t* port) {
  int sock = HANDLE_EINTR(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
  if (sock < 0) {
    PLOG(ERROR) << "socket() returns " << sock;
    return false;
  }
  base::ScopedFD scoped_socket(sock);
  CHECK(sock < FD_SETSIZE);

  int result =
      HANDLE_EINTR(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK));
  if (result < 0) {
    PLOG(ERROR) << "fcntl(NONBLOCK) returns " << result;
    return false;
  }

  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  result = HANDLE_EINTR(
      bind(sock, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)));
  if (result != kSyscallSuccess) {
    PLOG(ERROR) << "bind() returns " << result;
    return false;
  }

  int broadcast_enable = 1;
  result =
      HANDLE_EINTR(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable,
                              sizeof(broadcast_enable)));
  if (result != kSyscallSuccess) {
    PLOG(ERROR) << "setsockopt(SO_BROADCAST) returns " << result;
    return false;
  }

  socklen_t local_len = sizeof(local);
  result = HANDLE_EINTR(getsockname(
      sock, reinterpret_cast<struct sockaddr*>(&local), &local_len));
  if (result != kSyscallSuccess || local.sin_port == 0) {
    PLOG(ERROR) << "getsockname() returns " << result;
    return false;
  }

  *broadcast_socket = scoped_socket.release();
  *port = ntohs(local.sin_port);
  LOG(INFO) << "Bound to port " << ntohs(*port);

  return true;
}

static std::vector<ScannerInfo> SendProbeAndListen(uint16_t probe_socket) {
  std::vector<ScannerInfo> scanners;
  struct sockaddr_in broadcast;
  memset(&broadcast, 0, sizeof(broadcast));
  broadcast.sin_family = AF_INET;
  broadcast.sin_addr.s_addr = INADDR_BROADCAST;
  broadcast.sin_port = htons(kEpsonProbePort);
  int result = HANDLE_EINTR(sendto(
      probe_socket, kProbePacket, sizeof(kProbePacket), 0,
      reinterpret_cast<struct sockaddr*>(&broadcast), sizeof(broadcast)));
  if (result != sizeof(kProbePacket)) {
    LOG(ERROR) << "sendto() returns " << result << ": "
               << (result < 0 ? strerror(errno) : "");
    return scanners;
  }

  std::unordered_set<std::string> names;
  struct timeval maximum_wait_duration = {kReplyWaitTimeSeconds, 0};
  struct timeval now, end_time;
  CHECK(GetTimeMonotonic(&now));
  timeradd(&now, &maximum_wait_duration, &end_time);
  do {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(probe_socket, &read_fds);

    struct timeval wait_duration;
    timersub(&end_time, &now, &wait_duration);
    result = HANDLE_EINTR(
        select(probe_socket + 1, &read_fds, nullptr, nullptr, &wait_duration));
    if (result < 0) {
      PLOG(ERROR) << "select() returns " << result;
      break;
    }

    if (result == 0) {
      break;
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    socklen_t remote_len = sizeof(remote);

    char response[kExpectedReplySize];
    result = HANDLE_EINTR(recvfrom(probe_socket, response, sizeof(response), 0,
                                   reinterpret_cast<struct sockaddr*>(&remote),
                                   &remote_len));
    if (result < 0) {
      PLOG(ERROR) << "recvfrom() returns " << result;
      break;
    }

    if (result == kExpectedReplySize &&
        memcmp(response, kReplyPrefix, sizeof(kReplyPrefix) - 1) == 0) {
      char* ip_address_string = inet_ntoa(remote.sin_addr);
      std::string device_name =
          std::string(kEpsonDeviceNamePrefix) + ip_address_string;

      if (names.count(device_name) == 0) {
        names.insert(device_name);
        // We don't use anything from the response; neither does sane-backends.
        ScannerInfo info;
        info.set_name(device_name);
        info.set_manufacturer(kScannerManufacturerEpson);
        info.set_model(kScannerModelNetwork);
        info.set_type(kScannerTypeFlatbed);
        scanners.push_back(info);
      } else {
        LOG(INFO) << "Not adding device " << device_name << "; already in list";
      }
    } else {
      LOG(ERROR) << "Unexpected reply; length was " << result;
    }

    CHECK(GetTimeMonotonic(&now));
  } while (timercmp(&now, &end_time, <));
  return scanners;
}

std::vector<ScannerInfo> ProbeForScanners(FirewallManager* firewall_manager) {
  int probe_socket;
  uint16_t local_port;
  if (!CreateBroadcastSocket(&probe_socket, &local_port)) {
    return std::vector<ScannerInfo>();
  }
  base::ScopedFD scoped_socket(probe_socket);
  PortToken token = firewall_manager->RequestUdpPortAccess(local_port);
  std::vector<ScannerInfo> scanners = SendProbeAndListen(probe_socket);
  return scanners;
}

}  // namespace epson_probe

}  // namespace lorgnette
