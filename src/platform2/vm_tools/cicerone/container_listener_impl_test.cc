// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <dbus/message.h>
#include <gmock/gmock.h>
#include <grpcpp/impl/call.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <chromeos/dbus/service_constants.h>
#include <vm_applications/apps.pb.h>
#include <vm_protos/proto_bindings/container_host.grpc.pb.h>
#include <vm_protos/proto_bindings/container_host.pb.h>

#include "vm_tools/cicerone/container_listener_impl.h"
#include "vm_tools/cicerone/dbus_message_testing_helper.h"
#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/service_testing_helper.h"

namespace vm_tools {
namespace cicerone {

namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::Invoke;
using ::testing::Matches;
using ::testing::UnorderedElementsAreArray;
using ::testing::Unused;

constexpr char kDefaultPluginVmContainerName[] = "penguin";

class SysinfoProviderMock : public GuestMetrics::SysinfoProvider {
 public:
  MOCK_METHOD(int64_t, AmountOfTotalDiskSpace, (base::FilePath), ());
  MOCK_METHOD(int64_t, AmountOfFreeDiskSpace, (base::FilePath), ());
};

// Helper for testing proto-based MethodCalls sent to the dbus. Extracts the
// proto in from the MethodCall to |protobuf| so that it can be tested further.
// Returns an empty (but not NULL) dbus::Response.
//
// Does not confirm method name (a.k.a. GetMethod) or interface name; use
// HasMethodName and HasInterfaceName for that.
std::unique_ptr<dbus::Response> ProtoMethodCallHelper(
    dbus::MethodCall* method_call, google::protobuf::MessageLite* protobuf) {
  dbus::MessageReader reader(method_call);
  EXPECT_TRUE(reader.PopArrayOfBytesAsProto(protobuf));
  EXPECT_FALSE(reader.HasMoreData());

  // MockObjectProxy will take ownership of the created Response object. See
  // comments in MockObjectProxy.
  return dbus::Response::CreateEmpty();
}

// Same, but for method calls that just have a string.
std::unique_ptr<dbus::Response> StringMethodCallHelper(
    dbus::MethodCall* method_call, std::string* s) {
  dbus::MessageReader reader(method_call);
  EXPECT_TRUE(reader.PopString(s));
  EXPECT_FALSE(reader.HasMoreData());
  return dbus::Response::CreateEmpty();
}

// Same but for signals
void ProtoSignalHelper(dbus::Signal* signal,
                       google::protobuf::MessageLite* protobuf) {
  dbus::MessageReader reader(signal);
  EXPECT_TRUE(reader.PopArrayOfBytesAsProto(protobuf));
  EXPECT_FALSE(reader.HasMoreData());
}

TEST(ContainerListenerImplTest,
     ValidContainerShutdownCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ContainerShutdownInfo request;
  vm_tools::EmptyMessage response;
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);

  ContainerShutdownSignal shutdown_result;
  EXPECT_CALL(test_framework.get_mock_exported_object(),
              SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                               HasMethodName(kContainerShutdownSignal))))
      .WillOnce(Invoke([&shutdown_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &shutdown_result);
      }));
  std::string unregister_hostname;
  EXPECT_CALL(test_framework.get_mock_crosdns_service_proxy(),
              CallMethodAndBlock(
                  AllOf(HasInterfaceName(crosdns::kCrosDnsInterfaceName),
                        HasMethodName(crosdns::kRemoveHostnameIpMappingMethod)),
                  _))
      .WillOnce(
          Invoke([&unregister_hostname](dbus::MethodCall* method_call, Unused) {
            return StringMethodCallHelper(method_call, &unregister_hostname);
          }));

  grpc::ServerContext ctx;
  grpc::Status status = test_framework.get_service()
                            .GetContainerListenerImpl()
                            ->ContainerShutdown(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(shutdown_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(shutdown_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(shutdown_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);

  EXPECT_EQ(unregister_hostname,
            ServiceTestingHelper::kDefaultContainerHostname);
}

void ValidUpdateApplicationListCallShouldProduceDBusMessageGeneric(
    bool plugin_vm, const char* container_name) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  if (plugin_vm)
    test_framework.SetUpPluginVm();
  else
    test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::UpdateApplicationListRequest request;
  vm_tools::EmptyMessage response;

  const std::string kDesktopFileId = "nethack-x11";
  const std::string kName = "Nethack";
  const std::string kComment = "Get the amulet!";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  vm_tools::container::Application* application = request.add_application();
  application->set_desktop_file_id(kDesktopFileId);
  application->mutable_name()->add_values()->set_value(kName);
  application->mutable_comment()->add_values()->set_value(kComment);
  application->set_no_display(false);

  vm_tools::apps::ApplicationList dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_vm_applications_service_proxy(),
      CallMethodAndBlock(
          AllOf(
              HasInterfaceName(vm_tools::apps::kVmApplicationsServiceInterface),
              HasMethodName(
                  vm_tools::apps::
                      kVmApplicationsServiceUpdateApplicationListMethod)),
          _))
      .WillOnce(Invoke([&dbus_result](dbus::MethodCall* method_call, Unused) {
        return ProtoMethodCallHelper(method_call, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status = test_framework.get_service()
                            .GetContainerListenerImpl()
                            ->UpdateApplicationList(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(), container_name);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  ASSERT_EQ(dbus_result.apps_size(), 1);
  const vm_tools::apps::App& dbus_app = dbus_result.apps(0);
  EXPECT_EQ(dbus_app.desktop_file_id(), kDesktopFileId);
  const vm_tools::apps::App::LocaleString& dbus_name = dbus_app.name();
  ASSERT_EQ(dbus_name.values_size(), 1);
  EXPECT_EQ(dbus_name.values(0).value(), kName);
  EXPECT_EQ(dbus_name.values(0).locale(), "");
  const vm_tools::apps::App::LocaleString& dbus_comment = dbus_app.comment();
  ASSERT_EQ(dbus_comment.values_size(), 1);
  EXPECT_EQ(dbus_comment.values(0).value(), kComment);
  EXPECT_EQ(dbus_comment.values(0).locale(), "");
  EXPECT_FALSE(dbus_app.no_display());
  EXPECT_EQ(dbus_app.mime_types_size(), 0);
  EXPECT_EQ(dbus_app.startup_wm_class(), "");
  EXPECT_FALSE(dbus_app.startup_notify());
  EXPECT_EQ(dbus_app.keywords().values_size(), 0);
  EXPECT_EQ(dbus_app.package_id(), "");
  EXPECT_EQ(dbus_app.extensions_size(), 0);
}

TEST(ContainerListenerImplTest,
     ValidUpdateApplicationListCallShouldProduceDBusMessageForDefaultVm) {
  ValidUpdateApplicationListCallShouldProduceDBusMessageGeneric(
      false /* plugin_vm */, ServiceTestingHelper::kDefaultContainerName);
}

TEST(ContainerListenerImplTest,
     ValidUpdateApplicationListCallShouldProduceDBusMessageForPluginVm) {
  ValidUpdateApplicationListCallShouldProduceDBusMessageGeneric(
      true /* plugin_vm */, kDefaultPluginVmContainerName);
}

vm_tools::container::Application::LocalizedString MakeLocalizedString(
    const std::string& field_name, int seed) {
  vm_tools::container::Application::LocalizedString result;
  for (int value = 0; value < seed; ++value) {
    vm_tools::container::Application::LocalizedString::StringWithLocale*
        locale = result.add_values();

    if ((value % 5) != 0) {
      locale->set_value(field_name +
                        ":value:" + base::NumberToString(seed * 1000 + value));
    }
    if ((value % 4) != 0) {
      locale->set_locale(
          field_name + ":locale:" + base::NumberToString(seed * 1000 + value));
    }
  }

  return result;
}

vm_tools::container::Application::LocaleStrings MakeLocaleStrings(
    const std::string& field_name, int seed) {
  vm_tools::container::Application::LocaleStrings result;
  for (int value = 0; value < seed; ++value) {
    vm_tools::container::Application::LocaleStrings::StringsWithLocale* locale =
        result.add_values();

    for (int sub_value = 0; sub_value < value; ++sub_value) {
      locale->add_value(
          field_name + ":value:" +
          base::NumberToString(seed * 1000 + value * 10 + sub_value));
    }
    if ((value % 4) != 0) {
      locale->set_locale(
          field_name + ":locale:" + base::NumberToString(seed * 1000 + value));
    }
  }

  return result;
}

// Make an UpdateApplicationListRequest with every field filled in and multiple
// entries in every repeated field.
vm_tools::container::UpdateApplicationListRequest
MakeComplexUpdateApplicationListRequest() {
  vm_tools::container::UpdateApplicationListRequest request;
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);

  for (int app_num = 0; app_num < 10; ++app_num) {
    vm_tools::container::Application* application = request.add_application();

    // Non-repeated fields:
    application->set_desktop_file_id("desktop:" +
                                     base::NumberToString(app_num));
    application->set_no_display((app_num % 2) == 0);
    application->set_startup_wm_class("startup_wm_class:" +
                                      base::NumberToString(app_num));
    application->set_startup_notify((app_num % 3) == 0);
    application->set_package_id("package_id:" + base::NumberToString(app_num));

    // Repeated fields:
    *application->mutable_name() = MakeLocalizedString("name", app_num);
    *application->mutable_comment() =
        MakeLocalizedString("comment", 10 - app_num);
    for (int mime_type = 0; mime_type < 5; ++mime_type) {
      application->add_mime_types(
          "mime:" + base::NumberToString(app_num * 1000 + mime_type));
    }
    *application->mutable_keywords() = MakeLocaleStrings("keyword", app_num);
    for (int extension = 0; extension < 5; ++extension) {
      application->add_extensions(
          "extension:" + base::NumberToString(app_num * 1000 + extension));
    }
  }
  return request;
}

void CompareLocaleString(
    const vm_tools::container::Application::LocalizedString& expected,
    const vm_tools::apps::App::LocaleString& actual) {
  // Order is not important, only existence.
  EXPECT_EQ(expected.values_size(), actual.values_size());
  std::set<int> expected_indexes_seen;
  for (const vm_tools::apps::App::LocaleString::Entry& actual_entry :
       actual.values()) {
    bool found = false;
    int expected_index = 0;
    while (!found && expected_index < expected.values_size()) {
      if (expected.values(expected_index).locale() == actual_entry.locale() &&
          expected.values(expected_index).value() == actual_entry.value() &&
          expected_indexes_seen.find(expected_index) ==
              expected_indexes_seen.end()) {
        found = true;
      } else {
        ++expected_index;
      }
    }

    EXPECT_TRUE(found) << "Could not find expected.values() with locale "
                       << actual_entry.locale() << " and value "
                       << actual_entry.value();
    expected_indexes_seen.insert(expected_index);
  }
  EXPECT_EQ(expected_indexes_seen.size(), actual.values_size());
}

void CompareLocaleStrings(
    const vm_tools::container::Application::LocaleStrings& expected,
    const vm_tools::apps::App::LocaleStrings& actual) {
  // Order is not important, only existence.
  EXPECT_EQ(expected.values_size(), actual.values_size());
  std::set<int> expected_indexes_seen;
  for (const vm_tools::apps::App::LocaleStrings::StringsWithLocale&
           actual_entry : actual.values()) {
    bool found = false;
    int expected_index = 0;
    while (!found && expected_index < expected.values_size()) {
      if (expected.values(expected_index).locale() == actual_entry.locale() &&
          Matches(UnorderedElementsAreArray(
              expected.values(expected_index).value()))(actual_entry.value()) &&
          expected_indexes_seen.find(expected_index) ==
              expected_indexes_seen.end()) {
        found = true;
      } else {
        ++expected_index;
      }
    }

    EXPECT_TRUE(found) << "Could not find expected.values() with locale "
                       << actual_entry.locale() << " and "
                       << actual_entry.value_size() << " values";
    expected_indexes_seen.insert(expected_index);
  }
  EXPECT_EQ(expected_indexes_seen.size(), actual.values_size());
}

void CompareInputApplicationToOutputApp(
    const vm_tools::container::Application& expected,
    const vm_tools::apps::App& actual) {
  // Compare non-repeated fields.
  EXPECT_EQ(expected.desktop_file_id(), actual.desktop_file_id());
  EXPECT_EQ(expected.no_display(), actual.no_display());
  EXPECT_EQ(expected.startup_wm_class(), actual.startup_wm_class());
  EXPECT_EQ(expected.startup_notify(), actual.startup_notify());
  EXPECT_EQ(expected.package_id(), actual.package_id());

  EXPECT_THAT(actual.mime_types(),
              UnorderedElementsAreArray(expected.mime_types()));

  CompareLocaleString(expected.name(), actual.name());
  CompareLocaleString(expected.comment(), actual.comment());
  CompareLocaleStrings(expected.keywords(), actual.keywords());

  EXPECT_THAT(actual.extensions(),
              UnorderedElementsAreArray(expected.extensions()));
}

// Ensures that all the entries in expected match the entries in actual. Allows
// different order of the applications and sub-fields. EXPECT fails if
// differences are found.
void CompareUpdateApplicationListRequestToApplicationList(
    const vm_tools::container::UpdateApplicationListRequest& expected,
    const vm_tools::apps::ApplicationList& actual) {
  EXPECT_EQ(actual.apps_size(), expected.application_size());
  std::set<int> expected_indexes_seen;
  for (const vm_tools::apps::App& actual_app : actual.apps()) {
    // Don't assume input & output order are the same, because that's not part
    // of the API contract. Assume desktop_file_id is unique, though, since
    // MakeComplexUpdateApplicationListRequest will do that.
    bool found = false;
    int expected_index = 0;
    while (!found && expected_index < expected.application_size()) {
      if (expected.application(expected_index).desktop_file_id() ==
          actual_app.desktop_file_id()) {
        found = true;
      } else {
        ++expected_index;
      }
    }

    ASSERT_TRUE(found)
        << "Could not find expected.application() with desktop_file_id "
        << actual_app.desktop_file_id();
    EXPECT_TRUE(expected_indexes_seen.find(expected_index) ==
                expected_indexes_seen.end())
        << "desktop_file_id " << actual_app.desktop_file_id()
        << " appears twice in actual";
    expected_indexes_seen.insert(expected_index);

    CompareInputApplicationToOutputApp(expected.application(expected_index),
                                       actual_app);
  }
  EXPECT_EQ(expected_indexes_seen.size(), actual.apps_size());
}

void LongerUpdateApplicationListCallShouldProduceDBusMessageGeneric(
    bool plugin_vm, const char* container_name) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  if (plugin_vm)
    test_framework.SetUpPluginVm();
  else
    test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::UpdateApplicationListRequest request(
      MakeComplexUpdateApplicationListRequest());
  vm_tools::EmptyMessage response;

  vm_tools::apps::ApplicationList dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_vm_applications_service_proxy(),
      CallMethodAndBlock(
          AllOf(
              HasInterfaceName(vm_tools::apps::kVmApplicationsServiceInterface),
              HasMethodName(
                  vm_tools::apps::
                      kVmApplicationsServiceUpdateApplicationListMethod)),
          _))
      .WillOnce(Invoke([&dbus_result](dbus::MethodCall* method_call, Unused) {
        return ProtoMethodCallHelper(method_call, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status = test_framework.get_service()
                            .GetContainerListenerImpl()
                            ->UpdateApplicationList(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(), container_name);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);

  CompareUpdateApplicationListRequestToApplicationList(request, dbus_result);
}

TEST(ContainerListenerImplTest,
     LongerUpdateApplicationListCallShouldProduceDBusMessageForDefaultVm) {
  LongerUpdateApplicationListCallShouldProduceDBusMessageGeneric(
      false /* plugin_vm */, ServiceTestingHelper::kDefaultContainerName);
}

TEST(ContainerListenerImplTest,
     LongerUpdateApplicationListCallShouldProduceDBusMessageForPluginVm) {
  LongerUpdateApplicationListCallShouldProduceDBusMessageGeneric(
      true /* plugin_vm */, kDefaultPluginVmContainerName);
}

void ValidOpenUrlCallShouldProduceDBusMessageGeneric(bool plugin_vm) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  if (plugin_vm)
    test_framework.SetUpPluginVm();
  else
    test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::OpenUrlRequest request;
  vm_tools::EmptyMessage response;

  const std::string kUrl = "whycrostiniisgreat.com";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_url(kUrl);

  std::string resulting_url;
  EXPECT_CALL(
      test_framework.get_mock_url_handler_service_proxy(),
      CallMethodAndBlock(
          AllOf(HasInterfaceName(chromeos::kUrlHandlerServiceInterface),
                HasMethodName(chromeos::kUrlHandlerServiceOpenUrlMethod)),
          _))
      .WillOnce(Invoke([&resulting_url](dbus::MethodCall* method_call, Unused) {
        return StringMethodCallHelper(method_call, &resulting_url);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->OpenUrl(
          &ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(resulting_url, kUrl);
}

TEST(ContainerListenerImplTest,
     ValidOpenUrlCallShouldProduceDBusMessageForDefaultVm) {
  ValidOpenUrlCallShouldProduceDBusMessageGeneric(false);
}

TEST(ContainerListenerImplTest,
     ValidOpenUrlCallShouldProduceDBusMessageForPluginVm) {
  ValidOpenUrlCallShouldProduceDBusMessageGeneric(true);
}

TEST(ContainerListenerImplTest,
     ValidInstallLinuxPackageProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::InstallLinuxPackageProgressInfo request;
  vm_tools::EmptyMessage response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::InstallLinuxPackageProgressInfo::DOWNLOADING);
  request.set_progress_percent(52);

  InstallLinuxPackageProgressSignal dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_exported_object(),
      SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                       HasMethodName(kInstallLinuxPackageProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->InstallLinuxPackageProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(),
            InstallLinuxPackageProgressSignal::DOWNLOADING);
  EXPECT_EQ(dbus_result.progress_percent(), 52);
  EXPECT_EQ(dbus_result.failure_details(), "");
}

TEST(ContainerListenerImplTest,
     FailureInstallLinuxPackageProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::InstallLinuxPackageProgressInfo request;
  vm_tools::EmptyMessage response;

  const std::string kFailureDetails = "I prefer not to.";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::InstallLinuxPackageProgressInfo::FAILED);
  request.set_failure_details(kFailureDetails);

  InstallLinuxPackageProgressSignal dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_exported_object(),
      SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                       HasMethodName(kInstallLinuxPackageProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->InstallLinuxPackageProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(), InstallLinuxPackageProgressSignal::FAILED);
  EXPECT_EQ(dbus_result.progress_percent(), 0);
  EXPECT_EQ(dbus_result.failure_details(), kFailureDetails);
}

TEST(ContainerListenerImplTest,
     ValidUninstallPackageProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::UninstallPackageProgressInfo request;
  vm_tools::EmptyMessage response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::UninstallPackageProgressInfo::UNINSTALLING);
  request.set_progress_percent(72);

  UninstallPackageProgressSignal dbus_result;
  EXPECT_CALL(test_framework.get_mock_exported_object(),
              SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                               HasMethodName(kUninstallPackageProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->UninstallPackageProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(), UninstallPackageProgressSignal::UNINSTALLING);
  EXPECT_EQ(dbus_result.progress_percent(), 72);
  EXPECT_EQ(dbus_result.failure_details(), "");
}

TEST(ContainerListenerImplTest,
     FailedUninstallPackageProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::UninstallPackageProgressInfo request;
  vm_tools::EmptyMessage response;

  const std::string kFailureDetails = "Hahaha NO";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(vm_tools::container::UninstallPackageProgressInfo::FAILED);
  request.set_failure_details(kFailureDetails);

  UninstallPackageProgressSignal dbus_result;
  EXPECT_CALL(test_framework.get_mock_exported_object(),
              SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                               HasMethodName(kUninstallPackageProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->UninstallPackageProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(), UninstallPackageProgressSignal::FAILED);
  EXPECT_EQ(dbus_result.progress_percent(), 0);
  EXPECT_EQ(dbus_result.failure_details(), kFailureDetails);
}

TEST(ContainerListenerImplTest, ValidOpenTerminalCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::OpenTerminalRequest request;
  vm_tools::EmptyMessage response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  *request.add_params() = "-c";
  *request.add_params() = "/bin/ls";
  *request.add_params() = "/tmp";

  vm_tools::apps::TerminalParams dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_vm_applications_service_proxy(),
      CallMethodAndBlock(
          AllOf(
              HasInterfaceName(vm_tools::apps::kVmApplicationsServiceInterface),
              HasMethodName(
                  vm_tools::apps::kVmApplicationsServiceLaunchTerminalMethod)),
          _))
      .WillOnce(Invoke([&dbus_result](dbus::MethodCall* method_call, Unused) {
        return ProtoMethodCallHelper(method_call, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->OpenTerminal(
          &ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  ASSERT_EQ(dbus_result.params_size(), 3);
  EXPECT_EQ(dbus_result.params(0), "-c");
  EXPECT_EQ(dbus_result.params(1), "/bin/ls");
  EXPECT_EQ(dbus_result.params(2), "/tmp");
}

TEST(ContainerListenerImplTest,
     ValidUpdateMimeTypesCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::UpdateMimeTypesRequest request;
  vm_tools::EmptyMessage response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  (*request.mutable_mime_type_mappings())["aiff"] = "audio/x-aiff";
  (*request.mutable_mime_type_mappings())["rar"] = "application/rar";
  (*request.mutable_mime_type_mappings())["png"] = "image/png";

  vm_tools::apps::MimeTypes dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_vm_applications_service_proxy(),
      CallMethodAndBlock(
          AllOf(
              HasInterfaceName(vm_tools::apps::kVmApplicationsServiceInterface),
              HasMethodName(
                  vm_tools::apps::kVmApplicationsServiceUpdateMimeTypesMethod)),
          _))
      .WillOnce(Invoke([&dbus_result](dbus::MethodCall* method_call, Unused) {
        return ProtoMethodCallHelper(method_call, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->UpdateMimeTypes(
          &ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  const auto& mime_type_mappings = dbus_result.mime_type_mappings();
  EXPECT_EQ(mime_type_mappings.size(), 3);
  auto aiff_iter = mime_type_mappings.find("aiff");
  ASSERT_TRUE(aiff_iter != mime_type_mappings.end());
  EXPECT_EQ(aiff_iter->second, "audio/x-aiff");
  auto rar_iter = mime_type_mappings.find("rar");
  ASSERT_TRUE(rar_iter != mime_type_mappings.end());
  EXPECT_EQ(rar_iter->second, "application/rar");
  auto png_iter = mime_type_mappings.find("png");
  ASSERT_TRUE(png_iter != mime_type_mappings.end());
  EXPECT_EQ(png_iter->second, "image/png");
}

TEST(ContainerListenerImplTest,
     ValidApplyAnsiblePlaybookProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ApplyAnsiblePlaybookProgressInfo request;
  vm_tools::EmptyMessage response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::ApplyAnsiblePlaybookProgressInfo::SUCCEEDED);

  ApplyAnsiblePlaybookProgressSignal dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_exported_object(),
      SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                       HasMethodName(kApplyAnsiblePlaybookProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->ApplyAnsiblePlaybookProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(),
            ApplyAnsiblePlaybookProgressSignal::SUCCEEDED);
  EXPECT_EQ(dbus_result.failure_details(), "");
}

TEST(ContainerListenerImplTest,
     FailedApplyAnsiblePlaybookProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ApplyAnsiblePlaybookProgressInfo request;
  vm_tools::EmptyMessage response;

  const std::string kFailureDetails = "Hahaha NO";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::ApplyAnsiblePlaybookProgressInfo::FAILED);
  request.set_failure_details(kFailureDetails);

  ApplyAnsiblePlaybookProgressSignal dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_exported_object(),
      SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                       HasMethodName(kApplyAnsiblePlaybookProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->ApplyAnsiblePlaybookProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(), ApplyAnsiblePlaybookProgressSignal::FAILED);
  EXPECT_EQ(dbus_result.failure_details(), kFailureDetails);
}

TEST(ContainerListenerImplTest,
     InProgressApplyAnsiblePlaybookProgressCallShouldProduceDBusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ApplyAnsiblePlaybookProgressInfo request;
  vm_tools::EmptyMessage response;

  const std::string kStatusString = "Yesh milord. More work?";
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  request.set_status(
      vm_tools::container::ApplyAnsiblePlaybookProgressInfo::IN_PROGRESS);
  request.add_status_string(kStatusString);

  ApplyAnsiblePlaybookProgressSignal dbus_result;
  EXPECT_CALL(
      test_framework.get_mock_exported_object(),
      SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                       HasMethodName(kApplyAnsiblePlaybookProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service()
          .GetContainerListenerImpl()
          ->ApplyAnsiblePlaybookProgress(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.container_name(),
            ServiceTestingHelper::kDefaultContainerName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(),
            ApplyAnsiblePlaybookProgressSignal::IN_PROGRESS);
  EXPECT_EQ(dbus_result.status_string(0), kStatusString);
}

TEST(ContainerListenerImplTest, ValidReportMetricsCallShouldAccumulateMetrics) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  // Fake an RPC from the guest containing two metrics.
  vm_tools::container::ReportMetricsRequest request;
  vm_tools::container::ReportMetricsResponse response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  vm_tools::container::Metric* m = request.add_metric();
  m->set_name("borealis-swap-kb-written");
  m->set_value(123456);
  m = request.add_metric();
  m->set_name("borealis-disk-kb-read");
  m->set_value(654321);

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
          &ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  // Force a call to GuestMetrics::ReportDailyMetrics, which should report all
  // eight disk metrics to UMA.  The two four which received data from the fake
  // RPC above should contain the reported data, and the other six should be
  // zero.
  EXPECT_CALL(*test_framework.GetMetricsLibraryMock(), SendToUMA(_, _, _, _, _))
      .Times(8)
      .WillRepeatedly([](const std::string& name, int sample, int min, int max,
                         int nbuckets) {
        if (name == "Borealis.Disk.SwapWritesDaily") {
          EXPECT_EQ(sample, 123456);
        } else if (name == "Borealis.Disk.StatefulReadsDaily") {
          EXPECT_EQ(sample, 654321);
        } else {
          // {Borealis,Crostini}.Disk.{SwapReads,StatefulWrites}Daily
          EXPECT_EQ(sample, 0);
        }
        return true;
      });
  test_framework.GetGuestMetrics()->ReportMetricsImmediatelyForTesting();
}

TEST(ContainerListenerImplTest,
     ReportingInodeCountShouldGenerateAndEmitSpaceMetrics) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();

  // Setup a mock provider for sysinfo.
  auto sysinfo_provider = std::make_unique<SysinfoProviderMock>();
  SysinfoProviderMock* sysinfo_provider_reference = sysinfo_provider.get();
  test_framework.GetGuestMetrics()->SetSysinfoProviderForTesting(
      std::move(sysinfo_provider));

  // Fake an RPC from the guest containing two metrics.
  vm_tools::container::ReportMetricsRequest request;
  vm_tools::container::ReportMetricsResponse response;

  // Setup metrics request.
  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  vm_tools::container::Metric* m = request.add_metric();
  m->set_name("borealis-inode-count");
  m->set_value(100);

  // Replace the concierge object proxy with our mock.
  EXPECT_CALL(test_framework.get_mock_bus(),
              GetObjectProxy(vm_tools::concierge::kVmConciergeServiceName, _))
      .WillOnce(
          testing::Return(&test_framework.get_mock_concierge_service_proxy()));

  // Replace the ListVmDisks request to concierge.
  EXPECT_CALL(
      test_framework.get_mock_concierge_service_proxy(),
      DoCallMethod(
          AllOf(HasInterfaceName(vm_tools::concierge::kVmConciergeInterface),
                HasMethodName(vm_tools::concierge::kListVmDisksMethod)),
          _, _))
      .WillOnce(Invoke([](dbus::MethodCall* method_call, int timeout,
                          base::OnceCallback<void(dbus::Response*)>* callback) {
        method_call->SetSerial(123);
        std::unique_ptr<dbus::Response> dbus_response(
            dbus::Response::FromMethodCall(method_call));
        dbus::MessageWriter writer(dbus_response.get());
        vm_tools::concierge::ListVmDisksResponse response;

        // Set the response.
        vm_tools::concierge::VmDiskInfo* image = response.add_images();
        image->set_name("borealis");
        image->set_size(1000000);
        image->set_path("/mnt/stateful/borealis.img");

        writer.AppendProtoAsArrayOfBytes(response);
        std::move(*callback).Run(std::move(dbus_response.get()));
      }));

  // Set the response to AmountOfTotalDiskSpace.
  EXPECT_CALL(*sysinfo_provider_reference,
              AmountOfTotalDiskSpace(base::FilePath("/mnt/stateful")))
      .WillOnce(testing::Return(2000000));
  // Set the response to AmountOfFreeDiskSpace.
  EXPECT_CALL(*sysinfo_provider_reference,
              AmountOfFreeDiskSpace(base::FilePath("/mnt/stateful")))
      .WillOnce(testing::Return(500000));

  // InodeRatioAtStartup [KiB] =
  // (1000000[image_size]/100[inode_count])/1024 = 9
  EXPECT_CALL(*test_framework.GetMetricsLibraryMock(),
              SendToUMA("Borealis.Disk.InodeRatioAtStartup", 9, 0, 10240, 50));
  // VMUsageToTotalSpacePercentageAtStartup [%] =
  // (1000000[image_size]/2000000[total_size])/100 = 50%
  EXPECT_CALL(*test_framework.GetMetricsLibraryMock(),
              SendPercentageToUMA(
                  "Borealis.Disk.VMUsageToTotalSpacePercentageAtStartup", 50));
  // VMUsageToTotalUsagePercentageAtStartup [%] =
  // (1000000[image_size]/(2000000[total_size] - 500000[free_space]))/100 = 66%
  EXPECT_CALL(*test_framework.GetMetricsLibraryMock(),
              SendPercentageToUMA(
                  "Borealis.Disk.VMUsageToTotalUsagePercentageAtStartup", 66));

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
          &ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();
}

TEST(ContainerListenerImplTest, ReportMetricsCallWithTooManyMetricsShouldFail) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ReportMetricsRequest request;
  vm_tools::container::ReportMetricsResponse response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  for (int i = 0; i < 20; ++i) {
    vm_tools::container::Metric* m = request.add_metric();
    m->set_name("a-fake-metric-whose-name-will-be-ignored");
    m->set_value(123456);
  }

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
          &ctx, &request, &response);
  ASSERT_FALSE(status.ok()) << status.error_message();
}

TEST(ContainerListenerImplTest, ReportMetricsCallWithBadMetricNameShouldFail) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ReportMetricsRequest request;
  vm_tools::container::ReportMetricsResponse response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  vm_tools::container::Metric* m = request.add_metric();
  m->set_name("This name contains forbidden characters!");
  m->set_value(123456);

  grpc::ServerContext ctx;
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
          &ctx, &request, &response);
  ASSERT_FALSE(status.ok()) << status.error_message();
}

TEST(ContainerListenerImplTest, ReportMetricsCallsShouldBeRateLimited) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::container::ReportMetricsRequest request;
  vm_tools::container::ReportMetricsResponse response;

  request.set_token(ServiceTestingHelper::kDefaultContainerToken);
  vm_tools::container::Metric* m = request.add_metric();
  m->set_name("borealis-swap-kb-written");
  m->set_value(123456);

  grpc::ServerContext ctx;
  // The first 6 calls should succeed.
  for (int i = 0; i < 6; i++) {
    grpc::Status status =
        test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
            &ctx, &request, &response);
    EXPECT_TRUE(status.ok()) << status.error_message();
    EXPECT_EQ(response.error(), 0);
  }
  // Seventh call should hit the rate limit and fail.
  grpc::Status status =
      test_framework.get_service().GetContainerListenerImpl()->ReportMetrics(
          &ctx, &request, &response);
  EXPECT_TRUE(status.ok()) << status.error_message();
  EXPECT_NE(response.error(), 0);
}

}  // namespace

}  // namespace cicerone
}  // namespace vm_tools
