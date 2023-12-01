// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/supplicant_manager.h"

#include <base/functional/bind.h>
#include <base/functional/callback.h>

#include "shill/control_interface.h"
#include "shill/event_dispatcher.h"
#include "shill/manager.h"
#include "shill/supplicant/supplicant_process_proxy_interface.h"

namespace shill {

SupplicantManager::ScopedSupplicantListener::ScopedSupplicantListener(
    SupplicantManager* supplicant_manager,
    const SupplicantListenerCallback& callback)
    : callback_(callback), supplicant_manager_(supplicant_manager) {
  supplicant_manager_->AddSupplicantListener(callback_);
}

SupplicantManager::ScopedSupplicantListener::~ScopedSupplicantListener() {
  supplicant_manager_->RemoveSupplicantListener(callback_);
}

SupplicantManager::SupplicantManager(Manager* manager)
    : control_interface_(manager->control_interface()),
      dispatcher_(manager->dispatcher()) {}

SupplicantManager::~SupplicantManager() {}

void SupplicantManager::Start() {
  proxy_ = control_interface_->CreateSupplicantProcessProxy(
      base::BindRepeating(&SupplicantManager::OnSupplicantPresence, AsWeakPtr(),
                          true),
      base::BindRepeating(&SupplicantManager::OnSupplicantPresence, AsWeakPtr(),
                          false));
}

void SupplicantManager::AddSupplicantListener(
    const SupplicantListenerCallback& present_callback) {
  listeners_.push_back(present_callback);
  // Give an immediate notification.
  if (present_)
    dispatcher_->PostTask(FROM_HERE, base::BindOnce(present_callback, true));
}

void SupplicantManager::RemoveSupplicantListener(
    const SupplicantListenerCallback& present_callback) {
  std::vector<SupplicantListenerCallback>::const_iterator it;
  for (it = listeners_.begin(); it != listeners_.end(); ++it) {
    if (*it == present_callback) {
      listeners_.erase(it);
      return;
    }
  }
}

void SupplicantManager::OnSupplicantPresence(bool present) {
  present_ = present;
  for (const auto& listener : listeners_)
    if (!listener.is_null())
      listener.Run(present);
}

void SupplicantManager::set_proxy(SupplicantProcessProxyInterface* proxy) {
  proxy_.reset(proxy);
}

}  // namespace shill
