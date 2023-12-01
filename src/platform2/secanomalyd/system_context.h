// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECANOMALYD_SYSTEM_CONTEXT_H_
#define SECANOMALYD_SYSTEM_CONTEXT_H_

#include <set>

#include <base/files/file_path.h>

#include <session_manager/dbus-proxies.h>

using SessionManagerProxy = org::chromium::SessionManagerInterfaceProxy;
using SessionManagerProxyInterface =
    org::chromium::SessionManagerInterfaceProxyInterface;

enum class LandlockState {
  kEnabled,
  kDisabled,
  kNotSupported,
  kUnknown,
};

class SystemContext {
 public:
  explicit SystemContext(SessionManagerProxyInterface* session_manager);
  virtual ~SystemContext() = default;

  // Updates all signals. This should be called at the beginning of each scan in
  // order to update the context, including the logged in state and the list of
  // previously observed known mounts. The only exception is the landlock status
  // signal, which is determined once during instantiation of this class.
  virtual void Refresh();

  bool IsUserLoggedIn() const { return logged_in_; }
  LandlockState GetLandlockState() const { return landlock_state_; }

  // Returns true if the `known_mount` was observed in the previous scan.
  bool IsMountPersistent(const base::FilePath& known_mount) const;
  void RecordKnownMountObservation(const base::FilePath& known_mount);

 protected:
  SystemContext() = default;
  void set_logged_in(bool logged_in) { logged_in_ = logged_in; }
  void set_previous_known_mounts(std::set<base::FilePath> known_mounts) {
    previous_known_mounts_.merge(known_mounts);
  }

 private:
  bool UpdateLoggedInState();
  void UpdateLandlockState();
  void UpdateKnownMountsState();

  // Un-owned.
  SessionManagerProxyInterface* session_manager_;
  bool logged_in_ = false;
  LandlockState landlock_state_;

  // These sets keep track of the known mounts observed during the past and
  // current scan intervals.
  std::set<base::FilePath> current_known_mounts_;
  std::set<base::FilePath> previous_known_mounts_;
};

#endif  // SECANOMALYD_SYSTEM_CONTEXT_H_
