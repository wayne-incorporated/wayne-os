// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shims/c_ppp.h"

#include <string>

#include <base/at_exit.h>
#include <base/logging.h>

#include "shill/shims/ppp.h"

using shill::shims::PPP;

namespace {
base::AtExitManager* g_exit_manager = nullptr;  // Cleans up LazyInstances.
}  // namespace

void PPPInit() {
  g_exit_manager = new base::AtExitManager();
  PPP::GetInstance()->Init();
}

int PPPHasSecret() {
  return 1;
}

int PPPGetSecret(char* username, char* password) {
  std::string user, pass;
  if (!PPP::GetInstance()->GetSecret(&user, &pass)) {
    return -1;
  }
  if (username) {
    strcpy(username, user.c_str());  // NOLINT(runtime/printf)
  }
  if (password) {
    strcpy(password, pass.c_str());  // NOLINT(runtime/printf)
  }
  return 1;
}

void PPPOnAuthenticateStart() {
  PPP::GetInstance()->OnAuthenticateStart();
}

void PPPOnAuthenticateDone() {
  PPP::GetInstance()->OnAuthenticateDone();
}

void PPPOnConnect(const char* ifname) {
  PPP::GetInstance()->OnConnect(ifname);
}

void PPPOnDisconnect() {
  PPP::GetInstance()->OnDisconnect();
}

void PPPOnExit(void* /*data*/, int arg) {
  PPP::GetInstance()->OnExit(arg);
  delete g_exit_manager;
  g_exit_manager = nullptr;
}
