// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_SERVICE_H_
#define SHILL_MOCK_SERVICE_H_

#include <string>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_piece.h>
#include <gmock/gmock.h>

#include "shill/refptr_types.h"
#include "shill/service.h"
#include "shill/technology.h"

namespace shill {

class MockService : public Service {
 public:
  // A constructor for the Service object
  explicit MockService(Manager* manager);
  MockService(const MockService&) = delete;
  MockService& operator=(const MockService&) = delete;

  ~MockService() override;

  MOCK_METHOD(void, AutoConnect, (), (override));
  MOCK_METHOD(void, Connect, (Error*, const char*), (override));
  MOCK_METHOD(void, Disconnect, (Error*, const char*), (override));
  MOCK_METHOD(void,
              DisconnectWithFailure,
              (Service::ConnectFailure, Error*, const char*),
              (override));
  MOCK_METHOD(void, UserInitiatedDisconnect, (const char*, Error*), (override));
  MOCK_METHOD(std::string, CalculateState, (Error*), (override));
  MOCK_METHOD(ConnectState, state, (), (const, override));
  MOCK_METHOD(void, SetState, (ConnectState), (override));
  MOCK_METHOD(void, SetProbeUrl, (const std::string&), (override));
  MOCK_METHOD(void,
              SetPortalDetectionFailure,
              (const std::string&, const std::string&, int),
              (override));
  MOCK_METHOD(bool, IsConnected, (Error*), (const, override));
  MOCK_METHOD(bool, IsConnecting, (), (const, override));
  MOCK_METHOD(bool, IsFailed, (), (const, override));
  MOCK_METHOD(bool, IsOnline, (), (const, override));
  MOCK_METHOD(bool, IsVisible, (), (const, override));
  MOCK_METHOD(void, SetFailure, (ConnectFailure), (override));
  MOCK_METHOD(ConnectFailure, failure, (), (const, override));
  MOCK_METHOD(RpcIdentifier, GetDeviceRpcId, (Error*), (const, override));
  MOCK_METHOD(const RpcIdentifier&, GetRpcIdentifier, (), (const, override));
  MOCK_METHOD(std::string, GetStorageIdentifier, (), (const, override));
  MOCK_METHOD(std::string,
              GetLoadableStorageIdentifier,
              (const StoreInterface&),
              (const, override));
  MOCK_METHOD(bool, Load, (const StoreInterface*), (override));
  MOCK_METHOD(bool, Unload, (), (override));
  MOCK_METHOD(bool, Save, (StoreInterface*), (override));
  MOCK_METHOD(void, Configure, (const KeyValueStore&, Error*), (override));
  MOCK_METHOD(bool,
              DoPropertiesMatch,
              (const KeyValueStore&),
              (const, override));
  MOCK_METHOD(bool, Is8021xConnectable, (), (const, override));
  MOCK_METHOD(bool, IsPortalDetectionDisabled, (), (const, override));
  MOCK_METHOD(bool, IsRemembered, (), (const, override));
  MOCK_METHOD(bool, HasProxyConfig, (), (const, override));
  MOCK_METHOD(void, SetAttachedNetwork, (base::WeakPtr<Network>), (override));
  MOCK_METHOD(bool, explicitly_disconnected, (), (const, override));
  MOCK_METHOD(const EapCredentials*, eap, (), (const, override));
  MOCK_METHOD(Technology, technology, (), (const, override));
  MOCK_METHOD(void, OnPropertyChanged, (base::StringPiece), (override));
  MOCK_METHOD(void, ClearExplicitlyDisconnected, (), (override));
  MOCK_METHOD(bool, link_monitor_disabled, (), (const, override));
  MOCK_METHOD(void, EnableAndRetainAutoConnect, (), (override));
  MOCK_METHOD(void, OnBeforeSuspend, (ResultCallback), (override));
  MOCK_METHOD(void, OnAfterResume, (), (override));
  MOCK_METHOD(void,
              OnDefaultServiceStateChanged,
              (const ServiceRefPtr&),
              (override));
  MOCK_METHOD(TetheringState, GetTethering, (), (const, override));

  // Set a string for this Service via |store|.  Can be wired to Save() for
  // test purposes.
  bool FauxSave(StoreInterface* store);
  const std::string& friendly_name() const { return Service::friendly_name(); }

 protected:
  void OnConnect(Error* error) override {}
  void OnDisconnect(Error* /*error*/, const char* /*reason*/) override {}

 private:
  RpcIdentifier id_;
  RpcIdentifier null_id_;
};

}  // namespace shill

#endif  // SHILL_MOCK_SERVICE_H_
