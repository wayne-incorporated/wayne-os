// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_MANAGER_H_
#define SHILL_SUPPLICANT_SUPPLICANT_MANAGER_H_

#include <memory>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>

namespace shill {

class ControlInterface;
class EventDispatcher;
class Manager;
class SupplicantProcessProxyInterface;

class SupplicantManager {
 public:
  using SupplicantListenerCallback = base::RepeatingCallback<void(bool)>;

  class ScopedSupplicantListener {
   public:
    ScopedSupplicantListener(SupplicantManager* supplicant_manager,
                             const SupplicantListenerCallback& callback);
    ScopedSupplicantListener(const ScopedSupplicantListener&) = delete;
    ScopedSupplicantListener& operator=(const ScopedSupplicantListener&) =
        delete;

    ~ScopedSupplicantListener();

   private:
    SupplicantListenerCallback callback_;
    SupplicantManager* const supplicant_manager_;
  };

  explicit SupplicantManager(Manager* manager);
  SupplicantManager(const SupplicantManager&) = delete;
  SupplicantManager& operator=(const SupplicantManager&) = delete;

  ~SupplicantManager();

  void Start();

  SupplicantProcessProxyInterface* proxy() const { return proxy_.get(); }

  base::WeakPtr<SupplicantManager> AsWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 private:
  friend class EthernetTest;
  friend class HotspotDeviceTest;
  friend class SupplicantManagerTest;
  friend class WiFiObjectTest;
  friend class DaemonTaskTest;

  FRIEND_TEST(DaemonTaskTest, SupplicantAppearsAfterStop);

  void AddSupplicantListener(
      const SupplicantListenerCallback& present_callback);
  void RemoveSupplicantListener(
      const SupplicantListenerCallback& present_callback);
  void OnSupplicantPresence(bool present);

  // Used by tests to set a mock SupplicantProcessProxy.  Takes ownership of
  // |proxy|.
  void set_proxy(SupplicantProcessProxyInterface* proxy);

  ControlInterface* control_interface_;
  EventDispatcher* dispatcher_;
  std::unique_ptr<SupplicantProcessProxyInterface> proxy_;
  std::vector<SupplicantListenerCallback> listeners_;
  bool present_ = false;

  base::WeakPtrFactory<SupplicantManager> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_MANAGER_H_
