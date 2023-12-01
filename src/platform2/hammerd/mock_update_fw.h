// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_MOCK_UPDATE_FW_H_
#define HAMMERD_MOCK_UPDATE_FW_H_

#include <string>

#include <gmock/gmock.h>

#include "hammerd/update_fw.h"

namespace hammerd {

// Since SendSubcommandReceiveResponse is using a void* pointer that can't
// be natively addressed by gMock, we defined a marco that makes side effect
// (the void *resp) be the one we desired.
ACTION_P(WriteResponse, ptr) {
  std::memcpy(arg2, ptr, arg3);
  return true;
}

class MockFirmwareUpdater : public FirmwareUpdaterInterface {
 public:
  MockFirmwareUpdater() = default;

  MOCK_METHOD(bool, LoadEcImage, (const std::string&), (override));
  MOCK_METHOD(bool, LoadTouchpadImage, (const std::string&), (override));
  MOCK_METHOD(bool, UsbSysfsExists, (), (override));
  MOCK_METHOD(UsbConnectStatus, ConnectUsb, (), (override));
  MOCK_METHOD(UsbConnectStatus, TryConnectUsb, (), (override));
  MOCK_METHOD(void, CloseUsb, (), (override));
  MOCK_METHOD(bool, SendFirstPdu, (), (override));
  MOCK_METHOD(void, SendDone, (), (override));
  MOCK_METHOD(bool, InjectEntropy, (), (override));
  MOCK_METHOD(bool, SendSubcommand, (UpdateExtraCommand), (override));
  MOCK_METHOD(bool,
              SendSubcommandWithPayload,
              (UpdateExtraCommand, const std::string&),
              (override));
  MOCK_METHOD(bool,
              SendSubcommandReceiveResponse,
              (UpdateExtraCommand, const std::string&, void*, size_t, bool),
              (override));
  MOCK_METHOD(bool, TransferImage, (SectionName), (override));
  MOCK_METHOD(bool, TransferTouchpadFirmware, (uint32_t, size_t), (override));
  MOCK_METHOD(SectionName, CurrentSection, (), (const, override));
  MOCK_METHOD(bool, ValidKey, (), (const, override));
  MOCK_METHOD(int, CompareRollback, (), (const, override));
  MOCK_METHOD(bool, VersionMismatch, (SectionName), (const, override));
  MOCK_METHOD(bool, IsSectionLocked, (SectionName), (const, override));
  MOCK_METHOD(bool, IsCritical, (), (const, override));
  MOCK_METHOD(bool, UnlockRW, (), (override));
  MOCK_METHOD(bool, IsRollbackLocked, (), (const, override));
  MOCK_METHOD(bool, UnlockRollback, (), (override));
  MOCK_METHOD(std::string, GetEcImageVersion, (), (const, override));
  MOCK_METHOD(std::string, ReadConsole, (), (override));
};

}  // namespace hammerd
#endif  // HAMMERD_MOCK_UPDATE_FW_H_
