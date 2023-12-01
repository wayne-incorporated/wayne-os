// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_MOCK_DLC_SERVICE_H_
#define DLCSERVICE_MOCK_DLC_SERVICE_H_

#include <string>

#include "dlcservice/dlc_service.h"

namespace dlcservice {

class MockDlcService : public DlcServiceInterface {
 public:
  MockDlcService() = default;

  MOCK_METHOD(void, Initialize, (), (override));
  MOCK_METHOD(bool,
              Install,
              (const InstallRequest&, brillo::ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              Uninstall,
              (const std::string& id, brillo::ErrorPtr* err),
              (override));
  MOCK_METHOD(DlcIdList, GetInstalled, (), (override));
  MOCK_METHOD(DlcIdList, GetExistingDlcs, (), (override));
  MOCK_METHOD(DlcIdList, GetDlcsToUpdate, (), (override));
  MOCK_METHOD((DlcBase*),
              GetDlc,
              (const DlcId& id, brillo::ErrorPtr* err),
              (override));
  MOCK_METHOD(bool,
              InstallCompleted,
              (const DlcIdList& ids, brillo::ErrorPtr* err),
              (override));
  MOCK_METHOD(bool,
              UpdateCompleted,
              (const DlcIdList& ids, brillo::ErrorPtr* err),
              (override));

 private:
  MockDlcService(const MockDlcService&) = delete;
  MockDlcService& operator=(const MockDlcService&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_MOCK_DLC_SERVICE_H_
