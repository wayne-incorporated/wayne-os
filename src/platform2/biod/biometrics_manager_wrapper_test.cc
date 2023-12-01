// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <utility>

#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/mock_exported_object_manager.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <dbus/property.h>

#include <biod/biometrics_manager_wrapper.h>
#include <biod/mock_biometrics_manager.h>
#include <biod/mock_biometrics_manager_record.h>
#include <biod/mock_session_state_manager.h>

namespace biod {
namespace {

using testing::_;
using testing::ByMove;
using testing::HasSubstr;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

constexpr char kUserID[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr char kUserID2[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static_assert(sizeof(kUserID) == 41);
static_assert(sizeof(kUserID2) == 41);

constexpr char kRecordID[] = "record";
constexpr char kLabel[] = "Finger";
constexpr char kClientConnectionName[] = ":1.33";

class BiometricsManagerWrapperTest : public ::testing::Test {
 public:
  BiometricsManagerWrapperTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);
    ON_CALL(*bus_, GetExportedObject)
        .WillByDefault(
            Invoke(this, &BiometricsManagerWrapperTest::GetExportedObject));

    proxy_ =
        new dbus::MockObjectProxy(bus_.get(), dbus::kDBusServiceName,
                                  dbus::ObjectPath(dbus::kDBusServicePath));

    ON_CALL(*bus_, GetObjectProxy(dbus::kDBusServiceName, _))
        .WillByDefault(Return(proxy_.get()));

    EXPECT_CALL(*proxy_, DoConnectToSignal(dbus::kDBusInterface, _, _, _))
        .WillRepeatedly(
            Invoke(this, &BiometricsManagerWrapperTest::ConnectToSignal));

    auto mock_biometrics_manager = std::make_unique<MockBiometricsManager>();
    bio_manager_ = mock_biometrics_manager.get();

    EXPECT_CALL(*bio_manager_, SetEnrollScanDoneHandler)
        .WillRepeatedly(SaveArg<0>(&on_enroll_scan_done));
    EXPECT_CALL(*bio_manager_, SetAuthScanDoneHandler)
        .WillRepeatedly(SaveArg<0>(&on_auth_scan_done));
    EXPECT_CALL(*bio_manager_, SetSessionFailedHandler)
        .WillRepeatedly(SaveArg<0>(&on_session_failed));

    EXPECT_CALL(*bio_manager_, GetType)
        .WillRepeatedly(Return(BIOMETRIC_TYPE_UNKNOWN));

    object_manager_ =
        std::make_unique<brillo::dbus_utils::MockExportedObjectManager>(
            bus_, dbus::ObjectPath(kBiodServicePath));
    session_manager_ = std::make_unique<MockSessionStateManager>();

    EXPECT_CALL(*session_manager_, AddObserver).Times(1);

    mock_bio_path_ = dbus::ObjectPath(
        base::StringPrintf("%s/%s", kBiodServicePath, "MockBiometricsManager"));

    auto sequencer =
        base::MakeRefCounted<brillo::dbus_utils::AsyncEventSequencer>();

    wrapper_.emplace(
        std::move(mock_biometrics_manager), object_manager_.get(),
        session_manager_.get(), mock_bio_path_,
        sequencer->GetHandler("Failed to register BiometricsManager", false));
  }

 protected:
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> proxy_;
  MockBiometricsManager* bio_manager_;
  std::unique_ptr<brillo::dbus_utils::MockExportedObjectManager>
      object_manager_;
  dbus::ObjectPath mock_bio_path_;
  std::map<std::string, scoped_refptr<dbus::MockExportedObject>>
      exported_objects_;
  std::unique_ptr<MockSessionStateManager> session_manager_;
  std::optional<BiometricsManagerWrapper> wrapper_;
  BiometricsManager::EnrollScanDoneCallback on_enroll_scan_done;
  BiometricsManager::AuthScanDoneCallback on_auth_scan_done;
  BiometricsManager::SessionFailedCallback on_session_failed;

  MOCK_METHOD(void,
              ResponseSender,
              (std::unique_ptr<dbus::Response> response),
              ());
  std::unique_ptr<dbus::Response> CallMethod(dbus::MethodCall* method_call);
  std::unique_ptr<dbus::Response> StartEnrollSession(
      const std::string& user_id,
      const std::string& label,
      dbus::ObjectPath* object_path);
  std::unique_ptr<dbus::Response> StartAuthSession(
      dbus::ObjectPath* object_path);
  void EmitNameOwnerChangedSignal(const std::string& name,
                                  const std::string& old_owner,
                                  const std::string& new_owner);
  std::unique_ptr<dbus::Response> GetRecordsForUser(
      const std::string& user_id, std::vector<dbus::ObjectPath>* paths);

 private:
  std::map<std::string, dbus::ObjectProxy::SignalCallback> signal_callbacks_;
  std::map<std::string, dbus::ExportedObject::MethodCallCallback>
      method_callbacks_;
  base::test::SingleThreadTaskEnvironment task_environment_;

  void ConnectToSignal(
      const std::string& interface_name,
      const std::string& signal_name,
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback* on_connected_callback);
  dbus::ExportedObject* GetExportedObject(const dbus::ObjectPath& object_path);
  void ExportMethod(
      const std::string& interface_name,
      const std::string& method_name,
      const dbus::ExportedObject::MethodCallCallback& method_call_callback,
      dbus::ExportedObject::OnExportedCallback on_exported_callback);
  bool ExportMethodAndBlock(
      const std::string& interface_name,
      const std::string& method_name,
      const dbus::ExportedObject::MethodCallCallback& method_call_callback);
};

void BiometricsManagerWrapperTest::ConnectToSignal(
    const std::string& interface_name,
    const std::string& signal_name,
    dbus::ObjectProxy::SignalCallback signal_callback,
    dbus::ObjectProxy::OnConnectedCallback* on_connected_callback) {
  EXPECT_EQ(interface_name, dbus::kDBusInterface);
  signal_callbacks_[signal_name] = std::move(signal_callback);
  task_environment_.GetMainThreadTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(*on_connected_callback), interface_name,
                     signal_name, true /* success */));
}

void BiometricsManagerWrapperTest::EmitNameOwnerChangedSignal(
    const std::string& name,
    const std::string& old_owner,
    const std::string& new_owner) {
  const auto it = signal_callbacks_.find("NameOwnerChanged");
  ASSERT_TRUE(it != signal_callbacks_.end())
      << "Client didn't register for NameOwnerChanged signal";

  dbus::Signal signal(dbus::kDBusInterface, "NameOwnerChanged");
  dbus::MessageWriter writer(&signal);
  writer.AppendString(name);
  writer.AppendString(old_owner);
  writer.AppendString(new_owner);

  it->second.Run(&signal);
}

dbus::ExportedObject* BiometricsManagerWrapperTest::GetExportedObject(
    const dbus::ObjectPath& object_path) {
  auto iter = exported_objects_.find(object_path.value());
  if (iter != exported_objects_.end()) {
    return iter->second.get();
  }

  scoped_refptr<dbus::MockExportedObject> exported_object =
      new dbus::MockExportedObject(bus_.get(), object_path);
  exported_objects_[object_path.value()] = exported_object;

  ON_CALL(*exported_object, ExportMethod)
      .WillByDefault(Invoke(this, &BiometricsManagerWrapperTest::ExportMethod));
  ON_CALL(*exported_object, ExportMethodAndBlock)
      .WillByDefault(
          Invoke(this, &BiometricsManagerWrapperTest::ExportMethodAndBlock));

  return exported_object.get();
}

void BiometricsManagerWrapperTest::ExportMethod(
    const std::string& interface_name,
    const std::string& method_name,
    const dbus::ExportedObject::MethodCallCallback& method_call_callback,
    dbus::ExportedObject::OnExportedCallback on_exported_callback) {
  std::string full_name = interface_name + "." + method_name;
  method_callbacks_[full_name] = method_call_callback;

  task_environment_.GetMainThreadTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(std::move(on_exported_callback), interface_name,
                                method_name, true /* success */));
}

bool BiometricsManagerWrapperTest::ExportMethodAndBlock(
    const std::string& interface_name,
    const std::string& method_name,
    const dbus::ExportedObject::MethodCallCallback& method_call_callback) {
  std::string full_name = interface_name + "." + method_name;
  method_callbacks_[full_name] = method_call_callback;

  return true;
}

std::unique_ptr<dbus::Response> BiometricsManagerWrapperTest::CallMethod(
    dbus::MethodCall* method_call) {
  std::string full_name =
      method_call->GetInterface() + "." + method_call->GetMember();

  std::unique_ptr<dbus::Response> response;
  EXPECT_CALL(*this, ResponseSender)
      .WillOnce([&response](std::unique_ptr<dbus::Response> result) {
        response = std::move(result);
      });

  auto response_sender = base::BindOnce(
      &BiometricsManagerWrapperTest::ResponseSender, base::Unretained(this));
  method_call->SetSerial(1);
  method_call->SetSender(kClientConnectionName);

  auto iter = method_callbacks_.find(full_name);
  EXPECT_TRUE(iter != method_callbacks_.end());
  dbus::ExportedObject::MethodCallCallback& method_callback = iter->second;
  method_callback.Run(method_call, std::move(response_sender));

  return response;
}

std::unique_ptr<dbus::Response>
BiometricsManagerWrapperTest::StartEnrollSession(
    const std::string& user_id,
    const std::string& label,
    dbus::ObjectPath* object_path) {
  dbus::MethodCall start_enroll_session(
      kBiometricsManagerInterface, kBiometricsManagerStartEnrollSessionMethod);
  dbus::MessageWriter writer(&start_enroll_session);
  writer.AppendString(user_id);
  writer.AppendString(label);

  auto response = CallMethod(&start_enroll_session);
  if (response->GetMessageType() == dbus::Message::MESSAGE_METHOD_RETURN) {
    dbus::MessageReader reader(response.get());
    reader.PopObjectPath(object_path);
  }

  return response;
}

std::unique_ptr<dbus::Response> BiometricsManagerWrapperTest::StartAuthSession(
    dbus::ObjectPath* object_path) {
  dbus::MethodCall start_auth_session(kBiometricsManagerInterface,
                                      kBiometricsManagerStartAuthSessionMethod);

  auto response = CallMethod(&start_auth_session);
  if (response->GetMessageType() == dbus::Message::MESSAGE_METHOD_RETURN) {
    dbus::MessageReader reader(response.get());
    reader.PopObjectPath(object_path);
  }

  return response;
}

std::unique_ptr<dbus::Response> BiometricsManagerWrapperTest::GetRecordsForUser(
    const std::string& user_id, std::vector<dbus::ObjectPath>* paths) {
  dbus::MethodCall get_records_for_user(
      kBiometricsManagerInterface, kBiometricsManagerGetRecordsForUserMethod);
  dbus::MessageWriter writer(&get_records_for_user);
  writer.AppendString(user_id);

  auto response = CallMethod(&get_records_for_user);
  if (response->GetMessageType() == dbus::Message::MESSAGE_METHOD_RETURN) {
    dbus::MessageReader reader(response.get());
    dbus::MessageReader array_reader(nullptr);
    reader.PopArray(&array_reader);
    dbus::ObjectPath object_path;
    while (array_reader.HasMoreData()) {
      array_reader.PopObjectPath(&object_path);
      paths->emplace_back(std::move(object_path));
    }
  }

  return response;
}

TEST_F(BiometricsManagerWrapperTest, TestStartEnrollSession) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);
  dbus::ObjectPath expected_object_path(mock_bio_path_.value() +
                                        "/EnrollSession");
  EXPECT_EQ(object_path, expected_object_path);

  // Expect that enroll session will be finished on destruction of
  // the enroll_session object. EXPECT_CALL is able to catch calls from
  // enroll_session destructor which is called at the end of this
  // test.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(1);
}

TEST_F(BiometricsManagerWrapperTest, TestStartEnrollSessionThenCancel) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Cancel enroll session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(1);
  dbus::MethodCall cancel_enroll_session(kEnrollSessionInterface,
                                         kEnrollSessionCancelMethod);
  auto cancel_response = CallMethod(&cancel_enroll_session);

  // Make sure enroll session is not killed on destruction
  // of the enroll_session object. EXPECT_CALL is able to catch calls from
  // enroll_session destructor which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestEnrollSessionFinish) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Expect enroll session is active when not finished.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(0);

  BiometricsManager::EnrollStatus enroll_status = {false, 50};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS, enroll_status);

  // Finish enroll session.
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(1);

  BiometricsManager::EnrollStatus enroll_status_finish = {true, 100};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS,
                          enroll_status_finish);
}

TEST_F(BiometricsManagerWrapperTest, TestEnrollSessionSignal) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Expect enroll scan done signal is emitted when enroll session not finished.
  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, SendSignal).WillOnce([](dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
    EXPECT_EQ(signal->GetMember(), kBiometricsManagerEnrollScanDoneSignal);
    dbus::MessageReader reader(signal);
    EnrollScanDone proto;
    reader.PopArrayOfBytesAsProto(&proto);
    EXPECT_FALSE(proto.done());
    EXPECT_EQ(proto.scan_result(), ScanResult::SCAN_RESULT_SUCCESS);
    EXPECT_EQ(proto.percent_complete(), 50);
  });

  BiometricsManager::EnrollStatus enroll_status = {false, 50};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS, enroll_status);

  // Finish enroll session.
  EXPECT_CALL(*object, SendSignal).WillOnce([](dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
    EXPECT_EQ(signal->GetMember(), kBiometricsManagerEnrollScanDoneSignal);
    dbus::MessageReader reader(signal);
    EnrollScanDone proto;
    reader.PopArrayOfBytesAsProto(&proto);
    EXPECT_TRUE(proto.done());
    EXPECT_EQ(proto.scan_result(), ScanResult::SCAN_RESULT_SUCCESS);
    EXPECT_EQ(proto.percent_complete(), 100);
  });

  BiometricsManager::EnrollStatus enroll_status_finish = {true, 100};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS,
                          enroll_status_finish);
}

TEST_F(BiometricsManagerWrapperTest, TestEnrollSessionRefreshRecords) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Expect we won't refresh records when enroll session is not finished.
  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(0);

  BiometricsManager::EnrollStatus enroll_status = {false, 50};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS, enroll_status);

  // Finish enroll session.
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(1);

  BiometricsManager::EnrollStatus enroll_status_finish = {true, 100};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS,
                          enroll_status_finish);
}

TEST_F(BiometricsManagerWrapperTest, TestOnEnrollScanDoneWithoutActiveSession) {
  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  // Expect we won't refresh records when enroll session was not started.
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(0);
  // Expect that no signal will be sent when there is no enroll session.
  EXPECT_CALL(*object, SendSignal).Times(0);

  BiometricsManager::EnrollStatus enroll_status_finish = {true, 100};
  on_enroll_scan_done.Run(ScanResult::SCAN_RESULT_SUCCESS,
                          enroll_status_finish);
}

TEST_F(BiometricsManagerWrapperTest, TestStartEnrollSessionFailed) {
  dbus::ObjectPath object_path;
  // Empty enroll session indicates that we were not able to start
  // enroll session.
  auto enroll_session = BiometricsManager::EnrollSession();
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() == dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest,
       TestStartEnrollSessionFailedNoPrimaryUser) {
  dbus::ObjectPath object_path;
  EXPECT_CALL(*bio_manager_, StartEnrollSession).Times(0);
  // Empty string means that primary user is not set.
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(""));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() == dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestStartEnrollSessionFailedWithErrors) {
  dbus::ObjectPath object_path;
  const std::string enroll_session_error = kFpHwUnavailable;
  auto enroll_session = BiometricsManager::EnrollSession();
  enroll_session.set_error(enroll_session_error);

  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_ERROR);
  EXPECT_THAT(response->ToString(), testing::HasSubstr(kFpHwUnavailable));
}

TEST_F(BiometricsManagerWrapperTest, TestOnSessionFailedEndsEnrollSession) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Fail enroll session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(1);
  on_session_failed.Run();

  // Make sure enroll session is not killed on destruction
  // of the enroll_session object. EXPECT_CALL is able to catch calls from
  // enroll_session destructor which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestEnrollOnSessionFailedSendSignal) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, SendSignal).WillOnce([](dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
    EXPECT_EQ(signal->GetMember(), kBiometricsManagerSessionFailedSignal);
  });

  // Fail enroll session.
  on_session_failed.Run();
}

TEST_F(BiometricsManagerWrapperTest, TestEnrollSessionOwnerDies) {
  dbus::ObjectPath object_path;
  auto enroll_session = BiometricsManager::EnrollSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartEnrollSession)
      .WillOnce(Return(ByMove(std::move(enroll_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartEnrollSession(kUserID, kLabel, &object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Fail enroll session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(1);
  EmitNameOwnerChangedSignal(kClientConnectionName, kClientConnectionName, "");

  // Make sure enroll session is not killed on destruction
  // of the enroll_session object. EXPECT_CALL is able to catch calls from
  // enroll_session destructor which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndEnrollSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSession) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);
  dbus::ObjectPath expected_object_path(mock_bio_path_.value() +
                                        "/AuthSession");
  EXPECT_EQ(object_path, expected_object_path);

  // Expect that auth session will be killed on destruction of the auth_sesson
  // object. EXPECT_CALL is able to catch calls from auth_session destructor
  // which is called at the end of this test.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(1);
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionThenEnd) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Cancel auth session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(1);
  dbus::MethodCall end_auth_session(kAuthSessionInterface,
                                    kAuthSessionEndMethod);
  auto cancel_response = CallMethod(&end_auth_session);

  // Make sure auth session is not killed on destruction of the auth_session
  // object. EXPECT_CALL is able to catch calls from auth_session destructor
  // which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionSuccess) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Expect that calling OnAuthScanDone doesn't end auth session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(0);

  BiometricsManager::AttemptMatches matches;
  FingerprintMessage result;
  matches.emplace(kUserID, std::vector<std::string>({kRecordID}));
  result.set_scan_result(ScanResult::SCAN_RESULT_SUCCESS);
  on_auth_scan_done.Run(std::move(result), std::move(matches));

  // Expect that auth session will be killed on destruction of the auth_session
  // object. EXPECT_CALL is able to catch calls from auth_session destructor
  // which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(1);
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionSuccessSignal) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  BiometricsManager::AttemptMatches matches;
  FingerprintMessage result;
  matches.emplace(kUserID, std::vector<std::string>({kRecordID}));
  result.set_scan_result(ScanResult::SCAN_RESULT_SUCCESS);

  // Check signal contents.
  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, SendSignal)
      .WillOnce([&result, this](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
        EXPECT_EQ(signal->GetMember(), kBiometricsManagerAuthScanDoneSignal);

        dbus::MessageReader reader(signal);
        dbus::MessageReader array_reader(nullptr);
        dbus::MessageReader dict_reader(nullptr);
        FingerprintMessage proto;
        std::string user_id;
        std::vector<dbus::ObjectPath> paths;
        dbus::ObjectPath record_path(mock_bio_path_.value() + "/Record" +
                                     kRecordID);

        EXPECT_TRUE(reader.PopArrayOfBytesAsProto(&proto));
        EXPECT_TRUE(reader.PopArray(&array_reader));
        EXPECT_TRUE(array_reader.PopDictEntry(&dict_reader));
        EXPECT_TRUE(dict_reader.PopString(&user_id));
        EXPECT_TRUE(dict_reader.PopArrayOfObjectPaths(&paths));
        EXPECT_EQ(paths, std::vector{record_path});
        EXPECT_EQ(result.scan_result(), proto.scan_result());
        EXPECT_EQ(user_id, kUserID);
      });

  on_auth_scan_done.Run(std::move(result), std::move(matches));
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionFailedWithErrors) {
  dbus::ObjectPath object_path;
  std::string auth_session_error = kFpHwUnavailable;
  auto auth_session = BiometricsManager::AuthSession();
  auth_session.set_error(auth_session_error);
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));

  auto response = StartAuthSession(&object_path);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_ERROR);
  EXPECT_THAT(response->ToString(), testing::HasSubstr(auth_session_error));
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionFailed) {
  dbus::ObjectPath object_path;
  // Empty auth session indicates that we were not able to start
  // enroll session.
  auto auth_session = BiometricsManager::AuthSession();
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() == dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestStartAuthSessionFailedNoPrimaryUser) {
  dbus::ObjectPath object_path;
  EXPECT_CALL(*bio_manager_, StartAuthSession).Times(0);
  // Empty string means that primary user is not set.
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(""));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() == dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestOnSessionFailedEndsAuthSession) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Cancel auth session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(1);
  on_session_failed.Run();

  // Make sure auth session is not killed on destruction of the auth_session
  // object. EXPECT_CALL is able to catch calls from auth_session destructor
  // which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestAuthOnSessionFailedSendsSignal) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, SendSignal).WillOnce([](dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
    EXPECT_EQ(signal->GetMember(), kBiometricsManagerSessionFailedSignal);
  });

  // Fail enroll session.
  on_session_failed.Run();
}

TEST_F(BiometricsManagerWrapperTest, TestAuthSessionOwnerDies) {
  dbus::ObjectPath object_path;
  auto auth_session = BiometricsManager::AuthSession(
      bio_manager_->session_weak_factory_.GetWeakPtr());
  EXPECT_CALL(*bio_manager_, StartAuthSession)
      .WillOnce(Return(ByMove(std::move(auth_session))));
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));

  auto response = StartAuthSession(&object_path);
  EXPECT_TRUE(response->GetMessageType() ==
              dbus::Message::MESSAGE_METHOD_RETURN);

  // Cancel auth session.
  auto iter = exported_objects_.find(object_path.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, Unregister).Times(1);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(1);
  EmitNameOwnerChangedSignal(kClientConnectionName, kClientConnectionName, "");

  // Make sure auth session is not killed on destruction of the auth_session
  // object. EXPECT_CALL is able to catch calls from auth_session destructor
  // which is called at the end of this test.
  EXPECT_CALL(*object, Unregister).Times(0);
  EXPECT_CALL(*bio_manager_, EndAuthSession).Times(0);
}

TEST_F(BiometricsManagerWrapperTest, TestRefreshRecordObjectsNoPrimaryUser) {
  // Empty string means that primary user is not set.
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(""));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(0);
  EXPECT_CALL(*object_manager_, ClaimInterface).Times(0);

  wrapper_->RefreshRecordObjects();
}

TEST_F(BiometricsManagerWrapperTest, TestRefreshRecordObjectsNoRecords) {
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(1);
  EXPECT_CALL(*object_manager_, ClaimInterface).Times(0);

  wrapper_->RefreshRecordObjects();
}

TEST_F(BiometricsManagerWrapperTest, TestRefreshRecordObjects) {
  auto record = std::make_unique<MockBiometricsManagerRecord>();
  std::string record_id(kRecordID);
  EXPECT_CALL(*record, GetId).WillRepeatedly(ReturnRef(record_id));
  EXPECT_CALL(*record, GetUserId).WillRepeatedly(Return(kUserID));

  std::vector<std::unique_ptr<BiometricsManagerRecord>> records;
  records.emplace_back(std::move(record));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords)
      .WillOnce(Return(ByMove(std::move(records))));

  // Calling ClaimInterface is enough to make sure that record was constructed.
  dbus::ObjectPath record_path(mock_bio_path_.value() + "/Record" + kRecordID);
  EXPECT_CALL(*object_manager_,
              ClaimInterface(record_path, dbus::kPropertiesInterface, _))
      .Times(1);
  EXPECT_CALL(*object_manager_,
              ClaimInterface(record_path, kRecordInterface, _))
      .Times(1);

  wrapper_->RefreshRecordObjects();

  // Check if proper record object path is returned
  std::vector<dbus::ObjectPath> paths;
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths, std::vector{record_path});
}

TEST_F(BiometricsManagerWrapperTest, TestGetRecordsForUser) {
  auto record = std::make_unique<MockBiometricsManagerRecord>();
  std::string record_id(kRecordID);
  EXPECT_CALL(*record, GetId).WillRepeatedly(ReturnRef(record_id));
  EXPECT_CALL(*record, GetUserId).WillRepeatedly(Return(kUserID));

  std::vector<std::unique_ptr<BiometricsManagerRecord>> records;
  records.emplace_back(std::move(record));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords)
      .WillOnce(Return(ByMove(std::move(records))));

  wrapper_->RefreshRecordObjects();

  // Check if for correct UserID proper record object path is returned.
  dbus::ObjectPath record_path(mock_bio_path_.value() + "/Record" + kRecordID);
  std::vector<dbus::ObjectPath> paths;
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths, std::vector{record_path});

  // Check if for wrong UserID, nothing is returned.
  paths.clear();
  GetRecordsForUser(kUserID2, &paths);
  EXPECT_EQ(paths.size(), 0);
}

TEST_F(BiometricsManagerWrapperTest, TestGetRecordsForUserNoPrimaryUser) {
  std::vector<dbus::ObjectPath> paths;
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(""));

  auto response = GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestRefreshRecordObjectsClearsRecords) {
  auto record = std::make_unique<MockBiometricsManagerRecord>();
  std::string record_id(kRecordID);
  EXPECT_CALL(*record, GetId).WillRepeatedly(ReturnRef(record_id));
  EXPECT_CALL(*record, GetUserId).WillRepeatedly(Return(kUserID));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));

  // Load one record.
  std::vector<std::unique_ptr<BiometricsManagerRecord>> records;
  records.emplace_back(std::move(record));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords)
      .WillOnce(Return(ByMove(std::move(records))));
  wrapper_->RefreshRecordObjects();

  // Get object path to loaded record.
  dbus::ObjectPath record_path(mock_bio_path_.value() + "/Record" + kRecordID);
  std::vector<dbus::ObjectPath> paths;
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths, std::vector{record_path});

  // Refresh record objects but don't load any records.
  records.clear();
  EXPECT_CALL(*bio_manager_, GetLoadedRecords)
      .WillOnce(Return(ByMove(std::move(records))));
  wrapper_->RefreshRecordObjects();

  // Check if there are no loaded records.
  paths.clear();
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths.size(), 0);
}

TEST_F(BiometricsManagerWrapperTest,
       TestRefreshRecordObjectsNoPrimaryUserClearsRecords) {
  auto record = std::make_unique<MockBiometricsManagerRecord>();
  std::string record_id(kRecordID);
  EXPECT_CALL(*record, GetId).WillRepeatedly(ReturnRef(record_id));
  EXPECT_CALL(*record, GetUserId).WillRepeatedly(Return(kUserID));
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));

  // Load one record.
  std::vector<std::unique_ptr<BiometricsManagerRecord>> records;
  records.emplace_back(std::move(record));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords)
      .WillOnce(Return(ByMove(std::move(records))));
  wrapper_->RefreshRecordObjects();

  // Get object path to loaded record.
  dbus::ObjectPath record_path(mock_bio_path_.value() + "/Record" + kRecordID);
  std::vector<dbus::ObjectPath> paths;
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths, std::vector{record_path});

  // Refresh record objects when primary user is not available.
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillRepeatedly(Return(""));
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(0);
  wrapper_->RefreshRecordObjects();

  // Check if there are no loaded records.
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  paths.clear();
  GetRecordsForUser(kUserID, &paths);
  EXPECT_EQ(paths.size(), 0);
}

TEST_F(BiometricsManagerWrapperTest, TestDestroyAllRecordsFailedNoPrimaryUser) {
  // Empty string means that primary user is not set.
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(""));
  EXPECT_CALL(*bio_manager_, DestroyAllRecords).Times(0);
  dbus::MethodCall destroy_all_records(
      kBiometricsManagerInterface, kBiometricsManagerDestroyAllRecordsMethod);

  auto response = CallMethod(&destroy_all_records);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestDestroyAllRecordsFailed) {
  EXPECT_CALL(*session_manager_, GetPrimaryUser).WillOnce(Return(kUserID));
  EXPECT_CALL(*bio_manager_, DestroyAllRecords).WillOnce(Return(false));
  dbus::MethodCall destroy_all_records(
      kBiometricsManagerInterface, kBiometricsManagerDestroyAllRecordsMethod);

  auto response = CallMethod(&destroy_all_records);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_ERROR);
}

TEST_F(BiometricsManagerWrapperTest, TestDestroyAllRecords) {
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  EXPECT_CALL(*bio_manager_, DestroyAllRecords).WillOnce(Return(true));
  // Expect refreshing records.
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(1);
  dbus::MethodCall destroy_all_records(
      kBiometricsManagerInterface, kBiometricsManagerDestroyAllRecordsMethod);

  auto response = CallMethod(&destroy_all_records);
  EXPECT_EQ(response->GetMessageType(), dbus::Message::MESSAGE_METHOD_RETURN);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedInResetSensor) {
  EXPECT_CALL(*bio_manager_, ResetSensor).WillOnce(Return(true));
  wrapper_->OnUserLoggedIn(kUserID, false);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedInResetSensorFailed) {
  EXPECT_CALL(*bio_manager_, ResetSensor).WillOnce(Return(false));
  wrapper_->OnUserLoggedIn(kUserID, false);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedInSendStatsTrue) {
  EXPECT_CALL(*bio_manager_, SendStatsOnLogin).Times(1);
  wrapper_->OnUserLoggedIn(kUserID, true);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedInSendStatsFalse) {
  EXPECT_CALL(*bio_manager_, SendStatsOnLogin).Times(0);
  wrapper_->OnUserLoggedIn(kUserID, false);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedIn) {
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  // User is logged in, so expect to allow disk access.
  EXPECT_CALL(*bio_manager_, SetDiskAccesses(true)).Times(1);
  // When access to records is allowed, then we expect to read records for user.
  EXPECT_CALL(*bio_manager_, ReadRecordsForSingleUser(kUserID)).Times(1);
  // Expect to get list of records that are loaded.
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(1);

  // Expect 'StatusChanged' signal is emitted.
  auto iter = exported_objects_.find(mock_bio_path_.value());
  ASSERT_TRUE(iter != exported_objects_.end());
  scoped_refptr<dbus::MockExportedObject> object = iter->second;
  EXPECT_CALL(*object, SendSignal).WillOnce([](dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), kBiometricsManagerInterface);
    EXPECT_EQ(signal->GetMember(), kBiometricsManagerStatusChangedSignal);
    dbus::MessageReader reader(signal);
    BiometricsManagerStatusChanged proto;
    reader.PopArrayOfBytesAsProto(&proto);
    EXPECT_EQ(proto.status(), BiometricsManagerStatus::INITIALIZED);
  });

  wrapper_->OnUserLoggedIn(kUserID, false);
}

TEST_F(BiometricsManagerWrapperTest, TestOnUserLoggedOut) {
  EXPECT_CALL(*session_manager_, GetPrimaryUser)
      .WillRepeatedly(Return(kUserID));
  // User is logged in, so expect to forbid disk access.
  EXPECT_CALL(*bio_manager_, SetDiskAccesses(false)).Times(1);
  // Remove all records from biometrics daemon memory and FPMCU.
  EXPECT_CALL(*bio_manager_, RemoveRecordsFromMemory).Times(1);
  // Expect that records are refreshed (part RefreshRecordObject()).
  EXPECT_CALL(*bio_manager_, GetLoadedRecords).Times(1);

  wrapper_->OnUserLoggedOut();
}

}  // namespace
}  // namespace biod
