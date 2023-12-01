// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_DEVICE_USER_H_
#define SECAGENTD_DEVICE_USER_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "base/files/file_path.h"
#include "base/functional/callback_forward.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "bindings/device_management_backend.pb.h"
#include "login_manager/proto_bindings/policy_descriptor.pb.h"
#include "session_manager/dbus-proxies.h"

namespace secagentd {
namespace testing {
class DeviceUserTestFixture;
}  // namespace testing

class DeviceUserInterface : public base::RefCounted<DeviceUserInterface> {
 public:
  virtual void RegisterSessionChangeHandler() = 0;
  virtual std::string GetDeviceUser() = 0;

  virtual ~DeviceUserInterface() = default;
};

class DeviceUser : public DeviceUserInterface {
 public:
  explicit DeviceUser(
      std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
          session_manager_);

  // Allow calling the private test-only constructor without befriending
  // scoped_refptr.
  template <typename... Args>
  static scoped_refptr<DeviceUser> CreateForTesting(Args&&... args) {
    return base::WrapRefCounted(new DeviceUser(std::forward<Args>(args)...));
  }

  // Start monitoring for login/out events.
  // Called when XDR reporting becomes enabled.
  void RegisterSessionChangeHandler() override;
  // Retrieves the current device user.
  std::string GetDeviceUser() override;

  DeviceUser(const DeviceUser&) = delete;
  DeviceUser(DeviceUser&&) = delete;
  DeviceUser& operator=(const DeviceUser&) = delete;
  DeviceUser& operator=(DeviceUser&&) = delete;

 private:
  friend class testing::DeviceUserTestFixture;

  explicit DeviceUser(
      std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
          session_manager,
      const base::FilePath& root_path);

  // Logs an error if registering for session changes fails.
  void HandleRegistrationResult(const std::string& interface,
                                const std::string& signal,
                                bool success);
  // Handles when there is a login/out event.
  void OnSessionStateChange(const std::string& state);
  // Updates the device id after a session change.
  void UpdateDeviceId();
  // Updates the user after a session change.
  void UpdateDeviceUser();
  // Retrieves the policy for the given account type and id.
  absl::StatusOr<enterprise_management::PolicyData> RetrievePolicy(
      login_manager::PolicyAccountType account_type,
      const std::string& account_id);
  // Return whether the current user is affiliated.
  bool IsAffiliated(const enterprise_management::PolicyData& user_policy);

  base::WeakPtrFactory<DeviceUser> weak_ptr_factory_;
  std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
      session_manager_;
  std::string device_user_ = "";
  std::string device_id_ = "";
  const base::FilePath root_path_;
};

}  // namespace secagentd
#endif  // SECAGENTD_DEVICE_USER_H_
