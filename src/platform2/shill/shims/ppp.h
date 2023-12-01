// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHIMS_PPP_H_
#define SHILL_SHIMS_PPP_H_

#include <memory>
#include <string>

#include <base/memory/ref_counted.h>
#include <base/lazy_instance.h>

namespace dbus {
class Bus;
}  // namespace dbus

namespace shill {

namespace shims {

class TaskProxy;

class PPP {
 public:
  ~PPP();

  // This is a singleton -- use PPP::GetInstance()->Foo().
  static PPP* GetInstance();

  void Init();

  bool GetSecret(std::string* username, std::string* password);
  void OnAuthenticateStart();
  void OnAuthenticateDone();
  void OnConnect(const std::string& ifname);
  void OnDisconnect();
  void OnExit(int exit_status);

 protected:
  PPP();
  PPP(const PPP&) = delete;
  PPP& operator=(const PPP&) = delete;

 private:
  friend base::LazyInstanceTraitsBase<PPP>;

  bool CreateProxy();
  void DestroyProxy();

  static std::string ConvertIPToText(const void* addr);

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<TaskProxy> proxy_;
  bool running_;
};

}  // namespace shims

}  // namespace shill

#endif  // SHILL_SHIMS_PPP_H_
