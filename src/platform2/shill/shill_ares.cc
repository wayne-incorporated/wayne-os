// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shill_ares.h"

namespace shill {

Ares::Ares() {}

Ares::~Ares() {}

Ares* Ares::GetInstance() {
  static base::NoDestructor<Ares> instance;
  return instance.get();
}

void Ares::Destroy(ares_channel channel) {
  ares_destroy(channel);
}

void Ares::GetHostByName(ares_channel channel,
                         const char* hostname,
                         int family,
                         ares_host_callback callback,
                         void* arg) {
  ares_gethostbyname(channel, hostname, family, callback, arg);
}

int Ares::GetSock(ares_channel channel, ares_socket_t* socks, int numsocks) {
  return ares_getsock(channel, socks, numsocks);
}

int Ares::InitOptions(ares_channel* channelptr,
                      struct ares_options* options,
                      int optmask) {
  return ares_init_options(channelptr, options, optmask);
}

void Ares::ProcessFd(ares_channel channel,
                     ares_socket_t read_fd,
                     ares_socket_t write_fd) {
  return ares_process_fd(channel, read_fd, write_fd);
}

void Ares::SetLocalDev(ares_channel channel, const char* local_dev_name) {
  ares_set_local_dev(channel, local_dev_name);
}

struct timeval* Ares::Timeout(ares_channel channel,
                              struct timeval* maxtv,
                              struct timeval* tv) {
  return ares_timeout(channel, maxtv, tv);
}

int Ares::SetServersCsv(ares_channel channel, const char* servers) {
  return ares_set_servers_csv(channel, servers);
}

}  // namespace shill
