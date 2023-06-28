// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_DEVICE_POLICY_SERVICE_H_
#define LOGIN_MANAGER_MOCK_DEVICE_POLICY_SERVICE_H_

#include "login_manager/device_policy_service.h"
#include "login_manager/mock_policy_store.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <crypto/scoped_nss_types.h>

#include "bindings/chrome_device_policy.pb.h"

namespace login_manager {
// Forward declaration.
typedef struct PK11SlotInfoStr PK11SlotInfo;

class MockDevicePolicyService : public DevicePolicyService {
 public:
  MockDevicePolicyService();
  explicit MockDevicePolicyService(PolicyKey* policy_key);
  ~MockDevicePolicyService() override;

  MOCK_METHOD(bool,
              Store,
              (const PolicyNamespace&,
               const std::vector<uint8_t>&,
               int,
               SignatureCheck,
               const Completion&),
              (override));
  MOCK_METHOD(bool,
              Retrieve,
              (const PolicyNamespace&, std::vector<uint8_t>*),
              (override));
  MOCK_METHOD(bool,
              Delete,
              (const PolicyNamespace&, SignatureCheck),
              (override));
  MOCK_METHOD(std::vector<std::string>,
              ListComponentIds,
              (PolicyDomain),
              (override));
  MOCK_METHOD(
      bool,
      CheckAndHandleOwnerLogin,
      (const std::string&, PK11SlotDescriptor*, bool*, brillo::ErrorPtr*),
      (override));
  MOCK_METHOD(bool,
              ValidateAndStoreOwnerKey,
              (const std::string&,
               const std::vector<uint8_t>&,
               PK11SlotDescriptor*),
              (override));
  MOCK_METHOD(bool, KeyMissing, (), (override));
  MOCK_METHOD(bool, Mitigating, (), (override));
  MOCK_METHOD(bool, Initialize, (), (override));
  MOCK_METHOD(void, ReportPolicyFileMetrics, (bool, bool), (override));
  MOCK_METHOD(void,
              ClearForcedReEnrollmentFlags,
              (const Completion&),
              (override));
  MOCK_METHOD(bool,
              ValidateRemoteDeviceWipeCommand,
              (const std::vector<uint8_t>&),
              (override));

  void set_crossystem(Crossystem* crossystem) { crossystem_ = crossystem; }
  void set_vpd_process(VpdProcess* vpd_process) { vpd_process_ = vpd_process; }
  void set_install_attributes_reader(
      InstallAttributesReader* install_attributes_reader) {
    install_attributes_reader_ = install_attributes_reader;
  }

  void OnPolicySuccessfullyPersisted() {
    OnPolicyPersisted(Completion(), dbus_error::kNone);
  }
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_DEVICE_POLICY_SERVICE_H_
