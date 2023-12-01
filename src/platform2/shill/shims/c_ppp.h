// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHIMS_C_PPP_H_
#define SHILL_SHIMS_C_PPP_H_

#if defined(__cplusplus)
extern "C" {
#endif

void PPPInit();
int PPPHasSecret();
int PPPGetSecret(char* username, char* password);
void PPPOnAuthenticateStart();
void PPPOnAuthenticateDone();
void PPPOnConnect(const char* ifname);
void PPPOnDisconnect();
void PPPOnExit(void* data, int arg);

#if defined(__cplusplus)
}
#endif

#endif  // SHILL_SHIMS_C_PPP_H_
