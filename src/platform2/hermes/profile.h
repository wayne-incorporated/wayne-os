// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_PROFILE_H_
#define HERMES_PROFILE_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <google-lpa/lpa/core/lpa.h>

#include "hermes/context.h"
#include "hermes/dbus_bindings/org.chromium.Hermes.Profile.h"

namespace hermes {

class Profile : public org::chromium::Hermes::ProfileInterface,
                public org::chromium::Hermes::ProfileAdaptor {
 public:
  template <typename... T>
  using DBusResponse = brillo::dbus_utils::DBusMethodResponse<T...>;

  static std::unique_ptr<Profile> Create(
      const lpa::proto::ProfileInfo& profile,
      const uint32_t physical_slot,
      const std::string& eid,
      bool is_pending,
      base::RepeatingCallback<void(const std::string&)> on_profile_enabled_cb);

  // org::chromium::Hermes::ProfileInterface overrides.
  void Enable(std::unique_ptr<DBusResponse<>> resp) override;
  void Disable(std::unique_ptr<DBusResponse<>> resp) override;
  void Rename(std::unique_ptr<DBusResponse<>> resp,
              const std::string& nickname) override;

  const dbus::ObjectPath& object_path() const { return object_path_; }
  ~Profile() override;

 private:
  explicit Profile(dbus::ObjectPath object_path, const uint32_t physical_slot);

  void OnEnabled(int error, std::shared_ptr<DBusResponse<>> response);
  void OnDisabled(int error, std::shared_ptr<DBusResponse<>> response);

  // Functions that call eponymous LPA methods. Called after channel acquisition
  void EnableProfile(std::unique_ptr<DBusResponse<>> response);
  void DisableProfile(std::unique_ptr<DBusResponse<>> response);

  // Sends notifications to smdp if !err. Always returns success on dbus
  void FinishProfileOpCb(EuiccOp euicc_op,
                         std::shared_ptr<DBusResponse<>> response,
                         int err);

  void SetNicknameMethod(std::string nickname,
                         std::unique_ptr<DBusResponse<>> response);
  void OnRestoreActiveSlot(std::shared_ptr<DBusResponse<>> response, int error);
  void SendDBusError(EuiccOp euicc_op,
                     std::shared_ptr<Profile::DBusResponse<>> response,
                     int lpa_error,
                     int modem_error);
  template <typename T>
  void RunOnSuccess(EuiccOp euicc_op,
                    base::OnceCallback<void(T)> cb,
                    T response,
                    int err);
  void SendDBusSuccess(EuiccOp euicc_op,
                       std::shared_ptr<Profile::DBusResponse<>> response);
  int GetMCCMNCAsInt();

  // Used to set other profiles as disabled when a new profile is enabled
  base::RepeatingCallback<void(const std::string&)> on_profile_enabled_cb_;

  Context* context_;
  dbus::ObjectPath object_path_;
  brillo::dbus_utils::DBusObject dbus_object_;
  const uint32_t physical_slot_;

  base::WeakPtrFactory<Profile> weak_factory_;
};

}  // namespace hermes

#endif  // HERMES_PROFILE_H_
