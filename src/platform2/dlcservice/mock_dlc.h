// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_MOCK_DLC_H_
#define DLCSERVICE_MOCK_DLC_H_

#include <optional>
#include <string>

#include <brillo/errors/error.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>

#include "dlcservice/dlc_interface.h"
#include "dlcservice/types.h"

namespace dlcservice {

class MockDlc : public DlcInterface {
 public:
  MockDlc() = default;

  MockDlc(const MockDlc&) = delete;
  MockDlc& operator=(const MockDlc&) = delete;

  MOCK_METHOD(bool, Initialize, (), (override));
  MOCK_METHOD(const DlcId&, GetId, (), (const, override));
  MOCK_METHOD(const std::string&, GetName, (), (const, override));
  MOCK_METHOD(const std::string&, GetDescription, (), (const, override));
  MOCK_METHOD(DlcState, GetState, (), (const, override));
  MOCK_METHOD(base::FilePath, GetRoot, (), (const, override));
  MOCK_METHOD(bool, IsInstalling, (), (const, override));
  MOCK_METHOD(bool, IsInstalled, (), (const, override));
  MOCK_METHOD(bool, IsVerified, (), (const, override));
  MOCK_METHOD(bool, IsScaled, (), (const, override));
  MOCK_METHOD(bool, HasContent, (), (const, override));
  MOCK_METHOD(uint64_t, GetUsedBytesOnDisk, (), (const, override));
  MOCK_METHOD(bool, IsPreloadAllowed, (), (const, override));
  MOCK_METHOD(bool, IsFactoryInstall, (), (const, override));
  MOCK_METHOD(bool, Install, (brillo::ErrorPtr * err), (override));
  MOCK_METHOD(bool,
              FinishInstall,
              (bool installed_by_ue, brillo::ErrorPtr* err),
              (override));
  MOCK_METHOD(bool,
              CancelInstall,
              (const brillo::ErrorPtr& err_in, brillo::ErrorPtr* err),
              (override));
  MOCK_METHOD(bool, Uninstall, (brillo::ErrorPtr * err), (override));
  MOCK_METHOD(bool, InstallCompleted, (brillo::ErrorPtr * err), (override));
  MOCK_METHOD(bool, UpdateCompleted, (brillo::ErrorPtr * err), (override));
  MOCK_METHOD(bool, MakeReadyForUpdate, (), (const, override));
  MOCK_METHOD(void, ChangeProgress, (double progress), (override));
  MOCK_METHOD(bool, SetReserve, (std::optional<bool> reserve), (override));
};

}  // namespace dlcservice

#endif  // DLCSERVICE_MOCK_DLC_H_
