// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stddef.h>
#include <stdint.h>

#include <iostream>
#include <memory>

#include <base/at_exit.h>
#include <base/notreached.h>
#include <brillo/syslog_logging.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include <gmock/gmock.h>
#include <vm_protos/proto_bindings/container_host.grpc.pb.h>
#include <vm_protos/proto_bindings/fuzzer.pb.h>

#include "vm_tools/cicerone/container_listener_impl.h"
#include "vm_tools/cicerone/mock_tremplin_stub.h"
#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/service_testing_helper.h"
#include "vm_tools/cicerone/tremplin_listener_impl.h"

namespace {

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::ReturnNull;
using ::testing::SetArgPointee;
using ::vm_tools::cicerone::ContainerListenerImpl;
using ::vm_tools::cicerone::CrashListenerImpl;
using ::vm_tools::cicerone::Service;
using ::vm_tools::cicerone::ServiceTestingHelper;
using ::vm_tools::cicerone::TremplinListenerImpl;

// Stuff to create & do once the first time the fuzzer runs.
struct SetupOnce {
  SetupOnce() {
    brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
    // Disable logging, as suggested in fuzzing instructions.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }

  // Protobuf Mutator will create invalid protos sometimes (with duplicate
  // map keys). Silence those warnings as well.
  protobuf_mutator::protobuf::LogSilencer log_silencer_;

  base::AtExitManager at_exit_;
};

void SetUpMockObjectProxy(
    const vm_tools::container::ContainerListenerFuzzerSingleAction& action,
    dbus::MockObjectProxy* mock_object_proxy) {
  if (action.return_dbus_response()) {
    EXPECT_CALL(*mock_object_proxy, CallMethodAndBlock(_, _))
        .WillRepeatedly(InvokeWithoutArgs(&dbus::Response::CreateEmpty));
    EXPECT_CALL(*mock_object_proxy, CallMethodAndBlockWithErrorDetails(_, _, _))
        .WillRepeatedly(InvokeWithoutArgs(&dbus::Response::CreateEmpty));
  } else {
    EXPECT_CALL(*mock_object_proxy, CallMethodAndBlock(_, _))
        .WillRepeatedly(ReturnNull());
    EXPECT_CALL(*mock_object_proxy, CallMethodAndBlockWithErrorDetails(_, _, _))
        .WillRepeatedly(ReturnNull());
  }
}

grpc::Status ToStatus(int integer_status_code) {
  grpc::StatusCode status_code =
      static_cast<grpc::StatusCode>(integer_status_code);
  grpc::Status status(status_code, "");
  return status;
}

std::unique_ptr<vm_tools::tremplin::MockTremplinStub> CreateMockTremplinStub(
    const vm_tools::container::ContainerListenerFuzzerSingleAction& action) {
  auto mock_tremplin_stub =
      std::make_unique<vm_tools::tremplin::MockTremplinStub>();

  EXPECT_CALL(*mock_tremplin_stub, CreateContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_create_container_response()),
                Return(ToStatus(action.tremplin_create_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, StartContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_start_container_response()),
                Return(ToStatus(action.tremplin_start_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, StopContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_stop_container_response()),
                Return(ToStatus(action.tremplin_stop_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, GetContainerUsername(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(
          SetArgPointee<2>(action.tremplin_get_container_username_response()),
          Return(ToStatus(action.tremplin_get_container_username_status()))));
  EXPECT_CALL(*mock_tremplin_stub, SetUpUser(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(SetArgPointee<2>(action.tremplin_set_up_user_response()),
                      Return(ToStatus(action.tremplin_set_up_user_status()))));
  EXPECT_CALL(*mock_tremplin_stub, GetContainerInfo(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_get_container_info_response()),
                Return(ToStatus(action.tremplin_get_container_info_status()))));
  EXPECT_CALL(*mock_tremplin_stub, SetTimezone(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(SetArgPointee<2>(action.tremplin_set_timezone_response()),
                      Return(ToStatus(action.tremplin_set_timezone_status()))));
  EXPECT_CALL(*mock_tremplin_stub, ExportContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_export_container_response()),
                Return(ToStatus(action.tremplin_export_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, ImportContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_import_container_response()),
                Return(ToStatus(action.tremplin_import_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, DeleteContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_delete_container_response()),
                Return(ToStatus(action.tremplin_delete_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, CancelExportContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(
          SetArgPointee<2>(action.tremplin_cancel_export_container_response()),
          Return(ToStatus(action.tremplin_cancel_export_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, CancelImportContainer(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(
          SetArgPointee<2>(action.tremplin_cancel_import_container_response()),
          Return(ToStatus(action.tremplin_cancel_import_container_status()))));
  EXPECT_CALL(*mock_tremplin_stub, StartLxd(_, _, _))
      .Times(AnyNumber())
      .WillOnce(DoAll(SetArgPointee<2>(action.tremplin_start_lxd_response()),
                      Return(ToStatus(action.tremplin_start_lxd_status()))));
  EXPECT_CALL(*mock_tremplin_stub, GetDebugInfo(_, _, _))
      .Times(AnyNumber())
      .WillOnce(
          DoAll(SetArgPointee<2>(action.tremplin_get_debug_info_response()),
                Return(ToStatus(action.tremplin_get_debug_info_status()))));

  return mock_tremplin_stub;
}

}  // namespace

DEFINE_PROTO_FUZZER(
    const vm_tools::container::ContainerListenerFuzzerInput& input) {
  static SetupOnce* setup_once = new SetupOnce;
  // Get rid of the unused variable warning.
  (void)setup_once;

  // We create the ServiceTestingHelper here, not in the static SetupOnce. This
  // is to force the threads to finish up before exiting this function --
  // destructing Service will force its threads to exit.
  ServiceTestingHelper test_framework(ServiceTestingHelper::NICE_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();

  for (const vm_tools::container::ContainerListenerFuzzerSingleAction& action :
       input.action()) {
    // Setting up the mocks for an action is relatively expensive, and the proto
    // fuzzer tends to create a great many empty actions, so we can save a lot
    // of time by skipping over those actions here.
    if (action.input_case() ==
        vm_tools::container::ContainerListenerFuzzerSingleAction::
            INPUT_NOT_SET) {
      continue;
    }

    ContainerListenerImpl* container_listener =
        test_framework.get_service().GetContainerListenerImpl();
    container_listener->OverridePeerAddressForTesting(action.peer_address());
    TremplinListenerImpl* tremplin_listener =
        test_framework.get_service().GetTremplinListenerImpl();
    tremplin_listener->OverridePeerAddressForTesting(action.peer_address());
    CrashListenerImpl* crash_listener =
        test_framework.get_service().GetCrashListenerImpl();

    SetUpMockObjectProxy(
        action, &test_framework.get_mock_vm_applications_service_proxy());
    SetUpMockObjectProxy(
        action, &test_framework.get_mock_vm_sk_forwarding_service_proxy());
    SetUpMockObjectProxy(
        action, &test_framework.get_mock_vm_disk_management_service_proxy());
    SetUpMockObjectProxy(action,
                         &test_framework.get_mock_url_handler_service_proxy());
    SetUpMockObjectProxy(action,
                         &test_framework.get_mock_crosdns_service_proxy());
    SetUpMockObjectProxy(action,
                         &test_framework.get_mock_concierge_service_proxy());

    test_framework.SetTremplinStub(ServiceTestingHelper::kDefaultOwnerId,
                                   ServiceTestingHelper::kDefaultVmName,
                                   CreateMockTremplinStub(action));

    grpc::ServerContext context;
    vm_tools::EmptyMessage response;
    vm_tools::tremplin::EmptyMessage tremplin_response;
    vm_tools::cicerone::MetricsConsentResponse metrics_response;
    vm_tools::container::ForwardSecurityKeyMessageResponse forward_sk_response;
    vm_tools::container::GetDiskInfoResponse get_disk_info_response;
    vm_tools::container::RequestSpaceResponse request_space_response;
    vm_tools::container::ReleaseSpaceResponse release_space_response;
    vm_tools::container::ReportMetricsResponse report_metrics_response;

    switch (action.input_case()) {
      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerStartupInfo:
        container_listener->ContainerReady(
            &context, &action.container_startup_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerShutdownInfo:
        container_listener->ContainerShutdown(
            &context, &action.container_shutdown_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUpdateApplicationListRequest:
        container_listener->UpdateApplicationList(
            &context, &action.update_application_list_request(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kOpenUrlRequest:
        container_listener->OpenUrl(&context, &action.open_url_request(),
                                    &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kSelectFileRequest:
        // ContainerListenerImpl::SelectFile() cannot be fuzzed since it blocks
        // the execution thread and expects a call to cicerone::FileSelected()
        // to signal the thread to continue.
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kInstallLinuxPackageProgressInfo:
        container_listener->InstallLinuxPackageProgress(
            &context, &action.install_linux_package_progress_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUninstallPackageProgressInfo:
        container_listener->UninstallPackageProgress(
            &context, &action.uninstall_package_progress_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kOpenTerminalRequest:
        container_listener->OpenTerminal(
            &context, &action.open_terminal_request(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUpdateMimeTypesRequest:
        container_listener->UpdateMimeTypes(
            &context, &action.update_mime_types_request(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kPendingAppListUpdateCount:
        container_listener->PendingUpdateApplicationListCalls(
            &context, &action.pending_app_list_update_count(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kTremplinStartupInfo:
        tremplin_listener->TremplinReady(
            &context, &action.tremplin_startup_info(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerCreationProgress:
        tremplin_listener->UpdateCreateStatus(
            &context, &action.container_creation_progress(),
            &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerDeletionProgress:
        tremplin_listener->UpdateDeletionStatus(
            &context, &action.container_deletion_progress(),
            &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerStartProgress:
        tremplin_listener->UpdateStartStatus(
            &context, &action.container_start_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerStopProgress:
        tremplin_listener->UpdateStopStatus(
            &context, &action.container_stop_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerExportProgress:
        tremplin_listener->UpdateExportStatus(
            &context, &action.container_export_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kContainerImportProgress:
        tremplin_listener->UpdateImportStatus(
            &context, &action.container_import_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kTremplinContainerShutdownInfo:
        tremplin_listener->ContainerShutdown(
            &context, &action.tremplin_container_shutdown_info(),
            &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kApplyAnsiblePlaybookProgressInfo:
        container_listener->ApplyAnsiblePlaybookProgress(
            &context, &action.apply_ansible_playbook_progress_info(),
            &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUpgradeContainerProgress:
        tremplin_listener->UpgradeContainerStatus(
            &context, &action.upgrade_container_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kMetricsConsentRequest:
        crash_listener->CheckMetricsConsent(&context, &response,
                                            &metrics_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kSendCrashReportRequest:
        crash_listener->SendCrashReport(
            &context, &action.send_crash_report_request(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kSendFailureReportRequest:
        crash_listener->SendFailureReport(
            &context, &action.send_failure_report_request(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUpdateListeningPorts:
        tremplin_listener->UpdateListeningPorts(
            &context, &action.update_listening_ports(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kStartLxdProgress:
        tremplin_listener->UpdateStartLxdStatus(
            &context, &action.start_lxd_progress(), &tremplin_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kFileWatchTriggeredInfo:
        container_listener->FileWatchTriggered(
            &context, &action.file_watch_triggered_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kLowDiskSpaceTriggeredInfo:
        container_listener->LowDiskSpaceTriggered(
            &context, &action.low_disk_space_triggered_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kForwardSecurityKeyMessageRequest:
        container_listener->ForwardSecurityKeyMessage(
            &context, &action.forward_security_key_message_request(),
            &forward_sk_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kGetDiskInfoRequest:
        container_listener->GetDiskInfo(
            &context, &action.get_disk_info_request(), &get_disk_info_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kRequestSpaceRequest:
        container_listener->RequestSpace(
            &context, &action.request_space_request(), &request_space_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kReleaseSpaceRequest:
        container_listener->ReleaseSpace(
            &context, &action.release_space_request(), &release_space_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kReportMetricsRequest:
        container_listener->ReportMetrics(&context,
                                          &action.report_metrics_request(),
                                          &report_metrics_response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kInhibitScreensaverInfo:
        container_listener->InhibitScreensaver(
            &context, &action.inhibit_screensaver_info(), &response);
        break;

      case vm_tools::container::ContainerListenerFuzzerSingleAction::
          kUninhibitScreensaverInfo:
        container_listener->UninhibitScreensaver(
            &context, &action.uninhibit_screensaver_info(), &response);
        break;

      default:
        NOTREACHED();
    }
  }
}
