// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/rtnl_listener.h"

#include "shill/net/rtnl_handler.h"

namespace shill {

RTNLListener::RTNLListener(
    int listen_flags,
    const base::RepeatingCallback<void(const RTNLMessage&)>& callback)
    : RTNLListener{listen_flags, callback, RTNLHandler::GetInstance()} {}

RTNLListener::RTNLListener(
    int listen_flags,
    const base::RepeatingCallback<void(const RTNLMessage&)>& callback,
    RTNLHandler* rtnl_handler)
    : listen_flags_(listen_flags),
      callback_(callback),
      rtnl_handler_(rtnl_handler) {
  rtnl_handler_->AddListener(this);
}

RTNLListener::~RTNLListener() {
  rtnl_handler_->RemoveListener(this);
}

void RTNLListener::NotifyEvent(int type, const RTNLMessage& msg) const {
  if (type & listen_flags_)
    callback_.Run(msg);
}

}  // namespace shill
