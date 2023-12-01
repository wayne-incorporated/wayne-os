// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MINIOS_INTERFACE_H_
#define MINIOS_MINIOS_INTERFACE_H_

#include <string>

#include <brillo/errors/error.h>
#include <minios/proto_bindings/minios.pb.h>

namespace minios {

class MiniOsInterface {
 public:
  virtual ~MiniOsInterface() = default;

  virtual bool GetState(State* state_out, brillo::ErrorPtr* error) = 0;
  virtual bool NextScreen(brillo::ErrorPtr* error) = 0;
  virtual void PressKey(uint32_t in_keycode) = 0;
  virtual bool PrevScreen(brillo::ErrorPtr* error) = 0;
  virtual bool Reset(brillo::ErrorPtr* error) = 0;
  virtual void SetNetworkCredentials(const std::string& in_ssid,
                                     const std::string& in_passphrase) = 0;
  virtual void StartRecovery(const std::string& in_ssid,
                             const std::string& in_passphrase) = 0;
};

}  // namespace minios

#endif  // MINIOS_MINIOS_INTERFACE_H_
