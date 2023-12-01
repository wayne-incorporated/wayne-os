// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_RTNL_LISTENER_H_
#define SHILL_NET_RTNL_LISTENER_H_

#include <base/functional/callback.h>
#include <base/observer_list_types.h>

#include "shill/net/shill_export.h"

namespace shill {

class RTNLHandler;
class RTNLMessage;

class SHILL_EXPORT RTNLListener : public base::CheckedObserver {
 public:
  RTNLListener(
      int listen_flags,
      const base::RepeatingCallback<void(const RTNLMessage&)>& callback);
  RTNLListener(
      int listen_flags,
      const base::RepeatingCallback<void(const RTNLMessage&)>& callback,
      RTNLHandler* rtnl_handler);
  RTNLListener(const RTNLListener&) = delete;
  RTNLListener& operator=(const RTNLListener&) = delete;

  ~RTNLListener();

  void NotifyEvent(int type, const RTNLMessage& msg) const;

 private:
  const int listen_flags_;
  const base::RepeatingCallback<void(const RTNLMessage&)> callback_;
  RTNLHandler* const rtnl_handler_;
};

}  // namespace shill

#endif  // SHILL_NET_RTNL_LISTENER_H_
