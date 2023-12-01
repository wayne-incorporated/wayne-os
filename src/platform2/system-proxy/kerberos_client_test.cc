// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/kerberos_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/message_loops/base_message_loop.h>
#include <dbus/kerberos/dbus-constants.h>
#include <dbus/object_path.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

using testing::_;
using testing::Return;

namespace system_proxy {
namespace {
constexpr char kKrb5ConfFile[] = "/tmp/krb5.conf";
constexpr char kCCacheFile[] = "/tmp/ccache";
constexpr char kPrincipalName[] = "user@TEST-REALM";

const char kKrb5Settings[] =
    "[libdefaults]\n"
    "\tdns_canonicalize_hostname = false\n"
    "\trdns = false\n"
    "\tdefault_realm = TEST-REALM\n";

std::string GetUpdatedConfig(const std::string& updated_config) {
  return base::StringPrintf("%s%s", kKrb5Settings, updated_config.c_str());
}

}  // namespace

// Implementation of KerberosClient that fakes dbus calls to kerberosd.
class FakeKerberosClient : public KerberosClient {
 public:
  explicit FakeKerberosClient(scoped_refptr<dbus::Bus> bus)
      : KerberosClient(bus) {}
  FakeKerberosClient(const FakeKerberosClient&) = delete;
  FakeKerberosClient& operator=(const FakeKerberosClient&) = delete;
  ~FakeKerberosClient() override = default;

  void SetFakeGetFilesResponse(const std::string& krb5_conf_data,
                               const std::string& ccache_data) {
    krb5_conf_data_ = krb5_conf_data;
    ccache_file_data_ = ccache_data;
  }

 protected:
  void GetFiles() override {
    auto dbus_response = dbus::Response::CreateEmpty();
    dbus::MessageWriter writer(dbus_response.get());

    kerberos::GetKerberosFilesResponse response;
    kerberos::KerberosFiles files;
    files.set_krb5conf(krb5_conf_data_);
    files.set_krb5cc(ccache_file_data_);
    *response.mutable_files() = files;

    writer.AppendProtoAsArrayOfBytes(response);

    OnGetFilesResponse(dbus_response.get());
  }

 private:
  // Values returned by the kerberosd service.
  std::string krb5_conf_data_;
  std::string ccache_file_data_;
};

class KerberosClientTest : public ::testing::Test {
 public:
  KerberosClientTest() {
    mock_kerberos_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        bus_.get(), kerberos::kKerberosServiceName,
        dbus::ObjectPath(kerberos::kKerberosServicePath));
    EXPECT_CALL(*bus_, GetObjectProxy(kerberos::kKerberosServiceName, _))
        .WillRepeatedly(Return(mock_kerberos_proxy_.get()));
    kerberos_client_.reset(new FakeKerberosClient(bus_));

    krb5_conf_file_path_ = base::FilePath(kKrb5ConfFile);
    ccache_file_path_ = base::FilePath(kCCacheFile);

    brillo_loop_.SetAsCurrent();
  }
  KerberosClientTest(const KerberosClientTest&) = delete;
  KerberosClientTest& operator=(const KerberosClientTest&) = delete;
  ~KerberosClientTest() override {
    // Clean-up
    kerberos_client_->DeleteFiles();
  }

 protected:
  std::unique_ptr<FakeKerberosClient> kerberos_client_;
  base::FilePath krb5_conf_file_path_;
  base::FilePath ccache_file_path_;

  scoped_refptr<dbus::MockBus> bus_ = new dbus::MockBus(dbus::Bus::Options());
  scoped_refptr<dbus::MockObjectProxy> mock_kerberos_proxy_;

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  brillo::BaseMessageLoop brillo_loop_{task_executor_.task_runner()};
};

// Test that the kerberos files are written and deleted correctly.
TEST_F(KerberosClientTest, KerberosEnabled) {
  base::DeleteFile(base::FilePath(kKrb5ConfFile));
  base::DeleteFile(base::FilePath(kCCacheFile));
  std::string actual_krb5config;
  std::string actual_ccache;

  EXPECT_FALSE(
      base::ReadFileToString(krb5_conf_file_path_, &actual_krb5config));
  EXPECT_FALSE(base::ReadFileToString(ccache_file_path_, &actual_ccache));

  kerberos_client_->SetFakeGetFilesResponse("fake conf", "fake ccache");
  kerberos_client_->SetKerberosEnabled(true);
  kerberos_client_->SetPrincipalName(kPrincipalName);

  ASSERT_TRUE(base::ReadFileToString(krb5_conf_file_path_, &actual_krb5config));
  ASSERT_TRUE(base::ReadFileToString(ccache_file_path_, &actual_ccache));
  EXPECT_EQ(GetUpdatedConfig("fake conf"), actual_krb5config);
  EXPECT_EQ("fake ccache", actual_ccache);

  kerberos_client_->SetKerberosEnabled(false);
  EXPECT_FALSE(
      base::ReadFileToString(krb5_conf_file_path_, &actual_krb5config));
  EXPECT_FALSE(base::ReadFileToString(ccache_file_path_, &actual_ccache));
}

// Test that the kerberos files are requested again when the
TEST_F(KerberosClientTest, SignalHandling) {
  std::string actual_krb5config;
  std::string actual_ccache;

  kerberos_client_->SetFakeGetFilesResponse("fake conf 1", "fake ccache 1");
  kerberos_client_->SetKerberosEnabled(true);
  kerberos_client_->SetPrincipalName(kPrincipalName);

  ASSERT_TRUE(base::ReadFileToString(krb5_conf_file_path_, &actual_krb5config));
  ASSERT_TRUE(base::ReadFileToString(ccache_file_path_, &actual_ccache));
  EXPECT_EQ(GetUpdatedConfig("fake conf 1"), actual_krb5config);
  EXPECT_EQ("fake ccache 1", actual_ccache);

  kerberos_client_->SetFakeGetFilesResponse("fake conf 2", "fake ccache 2");
  dbus::Signal signal_to_send(kerberos::kKerberosInterface,
                              kerberos::kKerberosFilesChangedSignal);
  kerberos_client_->OnKerberosFilesChanged(&signal_to_send);
  ASSERT_TRUE(base::ReadFileToString(krb5_conf_file_path_, &actual_krb5config));
  ASSERT_TRUE(base::ReadFileToString(ccache_file_path_, &actual_ccache));
  EXPECT_EQ(GetUpdatedConfig("fake conf 2"), actual_krb5config);
  EXPECT_EQ("fake ccache 2", actual_ccache);
}

}  // namespace system_proxy
