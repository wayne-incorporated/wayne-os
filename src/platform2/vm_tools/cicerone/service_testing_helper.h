// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_SERVICE_TESTING_HELPER_H_
#define VM_TOOLS_CICERONE_SERVICE_TESTING_HELPER_H_

#include <stdint.h>

#include <memory>
#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <metrics/metrics_library_mock.h>

#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/test_guest_metrics.h"

namespace vm_tools {
namespace cicerone {

// A set of helpers for writing unit tests and fuzz tests against Service and
// its various sub-objects.
class ServiceTestingHelper {
 public:
  // Constants for SetUpDefaultVm. NOTE: These values are reflected in the
  // fuzzer seed corpus, so don't change them unless you want to update the
  // fuzzer corpus.
  static constexpr char kDefaultVmName[] = "default_vm";
  static constexpr char kDefaultOwnerId[] = "default_user";
  static constexpr uint32_t kDefaultAddress = 0xab13cd01;
  static constexpr uint32_t kDefaultCid = 219;
  static constexpr char kDefaultPeerAddress[] = "vsock:219";
  static constexpr char kDefaultContainerName[] = "default_container";
  static constexpr char kDefaultContainerHostname[] =
      "default_container.default_vm.linux.test";
  static constexpr char kDefaultContainerToken[] =
      "3f1bc010-c87b-452c-8a6c-798edb9bf13a";

  // List of calls the Service accepts through its dbus interface
  enum DbusCall {
    kNotifyVmStarted = 0,
    kNotifyVmStopping,
    kNotifyVmStopped,
    kGetContainerToken,
    kLaunchContainerApplication,
    kGetContainerAppIcon,
    kLaunchVshd,
    kGetLinuxPackageInfo,
    kInstallLinuxPackage,
    kUninstallPackageOwningFile,
    kCreateLxdContainer,
    kDeleteLxdContainer,
    kStartLxdContainer,
    kStopLxdContainer,
    kSetTimezone,
    kGetLxdContainerUsername,
    kSetUpLxdContainerUser,
    kExportLxdContainer,
    kImportLxdContainer,
    kCancelExportLxdContainer,
    kCancelImportLxdContainer,
    kGetDebugInformation,
    kApplyAnsiblePlaybook,
    kConfigureForArcSideload,
    kConnectChunnel,
    kUpgradeContainer,
    kCancelUpgradeContainer,
    kStartLxd,
    kAddFileWatch,
    kRemoveFileWatch,
    kRegisterVshSession,
    kGetVshSession,
    kFileSelected,
    kAttachUsbToContainer,
    kDetachUsbFromContainer,
    kListRunningContainers,
    kGetGarconSessionInfo,
    kUpdateContainerDevices,

    kNumDbusCalls
  };

  // Unit tests want the normal mock behavior, but fuzz tests want the NiceMock
  // behavior, because they want to print as little as possible.
  enum MockType { NORMAL_MOCKS, NICE_MOCKS };

  // Sets up mock objects so that Service can be created, and then creates
  // Service, binding it to the mocks. Also gathers the dbus callbacks.
  explicit ServiceTestingHelper(MockType mock_type);
  ~ServiceTestingHelper();

  // The directory containing the AF_UNIX sockets needed to talk to the grpc
  // services.
  const base::FilePath& get_service_socket_path() const {
    return socket_temp_dir_.GetPath();
  }

  // The connection path for ContainerListenerImpl.
  std::string GetContainerListenerTargetAddress() const;

  // The connection path for TremplinListenerImpl.
  std::string GetTremplinListenerTargetAddress() const;

  // Sets up a default VM and a default container so that other calls can
  // succeed. The VM has the vm name kDefaultVmName, cid kDefaultCid,
  // owner_id kDefaultOwnerId. The container has the name kDefaultContainerName
  // and security token kDefaultContainerToken. NOTE: This calls
  // VerifyAndClearMockExpectations, so set up expectations after calling this
  // function.
  void SetUpDefaultVmAndContainer();

  // Sets up a plugin VM and so that other calls can succeed. The VM has the vm
  // name kDefaultVmName, zero-valued cid, owner_id kDefaultOwnerId and vm token
  // kDefaultContainerToken. NOTE: This calls VerifyAndClearMockExpectations, so
  // set up expectations after calling this function.
  void SetUpPluginVm();

  // Access to the mocks. We expect tests to set expectations using these
  // functions, so the returned objects are non-const. Ownership is retained by
  // the ServiceTestingHelper.
  dbus::MockBus& get_mock_bus() { return *mock_bus_; }
  dbus::MockExportedObject& get_mock_exported_object() {
    return *mock_exported_object_;
  }
  dbus::MockObjectProxy& get_mock_vm_applications_service_proxy() {
    return *mock_vm_applications_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_vm_disk_management_service_proxy() {
    return *mock_vm_disk_management_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_vm_sk_forwarding_service_proxy() {
    return *mock_vm_sk_forwarding_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_url_handler_service_proxy() {
    return *mock_url_handler_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_chunneld_service_proxy() {
    return *mock_chunneld_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_crosdns_service_proxy() {
    return *mock_crosdns_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_concierge_service_proxy() {
    return *mock_concierge_service_proxy_;
  }
  dbus::MockObjectProxy& get_mock_shill_manager_proxy() {
    return *mock_shill_manager_proxy_;
  }
  dbus::MockObjectProxy& get_mock_shadercached_proxy() {
    return *mock_shadercached_proxy_;
  }

  // Calls Mock::VerifyAndClearExpectations on all the above mocks.
  void VerifyAndClearMockExpectations();

  // Tells all the mock objects to not expect any DBus calls such as
  // CallMethodAndBlock, SendSignal, etc. Does not set expectations about
  // calls that would not (directly) send messages to other people on the DBus.
  // Does not set any expectations about calling Detach or other similar
  // shutdown-related functions.
  void ExpectNoDBusMessages();

  // Calls a DBus callback. This simulates a dbus call from the host OS.
  // |request| is the input proto; |response| will be filled in with the result
  // proto. |response| must be the correct type for the call. CHECK-fails on
  // error.
  void CallDBus(DbusCall call,
                const google::protobuf::MessageLite& request,
                google::protobuf::MessageLite* response);

  void SetTremplinStub(
      const std::string& owner_id,
      const std::string& vm_name,
      std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface>
          mock_tremplin_stub);

  GuestMetrics* GetGuestMetrics() {
    return service_->guest_metrics_for_testing();
  }

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        GetGuestMetrics()->metrics_library_for_testing());
  }

  // Number of times Service's quit closure was called.
  int get_quit_closure_called_count_() const {
    return quit_closure_called_count_;
  }

  // Access to the object being tested.
  Service& get_service() { return *service_; }

 private:
  struct DbusCallback {
    DbusCallback();
    ~DbusCallback();

    // Method name as registered on the dbus
    std::string method_name;

    dbus::ExportedObject::MethodCallCallback callback;
  };

  // Create service_ on the dbus thread. Signal |event| when finished.
  void CreateService(base::WaitableEvent* event);

  // Destroy service_ on the dbus thread. Signal |event| when finished.
  void DestroyService(base::WaitableEvent* event);

  std::string GetTremplinStubAddress() const;

  void SetupDBus(MockType mock_type);

  // Callback function; calls Service::SetTremplinStubOfVmForTesting
  // to point the VM to a mock tremplin stub, and then signals |event|.
  void SetTremplinStubOnDBusThread(
      const std::string& owner_id,
      const std::string& vm_name,
      std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface>
          mock_tremplin_stub,
      base::WaitableEvent* event);

  // Helper for SetUpDefaultVmAndContainer. Handles getting the default VM
  // set up and ready to go (and listening to our stub Tremplin server).
  void PretendDefaultVmStarted();

  // Helper for SetUpPluginVmAndContainer. Handles getting the plugin VM
  // set up and ready to go.
  void PretendPluginVmStarted();

  // Callback for CreateContainerWithTokenForTesting; calls
  // Service::CreateContainerWithTokenForTesting and then signals |event|.
  void CreateContainerWithTokenForTestingOnDBusThread(
      const std::string& owner_id,
      const std::string& vm_name,
      const std::string& container_name,
      const std::string& container_token,
      base::WaitableEvent* event);

  // Tells Service to create a container in the given VM with security token
  // |container_token|. VM must already exist.
  void CreateContainerWithTokenForTesting(const std::string& owner_id,
                                          const std::string& vm_name,
                                          const std::string& container_name,
                                          const std::string& container_token);

  // Helper for SetUpDefaultVmAndContainer. Handles telling the default VM
  // to set up the test container.
  void PretendDefaultContainerStarted();

  // Callback for CallDBus. Does the actual callback on the dbus thread. If
  // |event| is not null, signals the event when done.
  void CallDBusOnDBusThread(DbusCall call,
                            const google::protobuf::MessageLite* request,
                            google::protobuf::MessageLite* response,
                            base::WaitableEvent* event);

  void AssertOnDBusThread();

  void IncrementQuitClosure();

  // Set method_name for all entries in dbus_callbacks_.
  void SetDbusCallbackNames();

  // Invoked when Service calls ExportMethodAndBlock. Stores the callback in one
  // of the callbacks below so that we can simulate DBus calls later.
  bool StoreDBusCallback(
      const std::string& interface_name,
      const std::string& method_name,
      dbus::ExportedObject::MethodCallCallback method_call_callback);

  // Posts a task to call the given callback.
  void CallServiceAvailableCallback(
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback* callback);

  // Number of times Service called its quit closure.
  int quit_closure_called_count_;

  // Serial number for DBus messages.
  int dbus_serial_;

  // Temporary directory where we will store our sockets.
  base::ScopedTempDir socket_temp_dir_;

  // The thread we have Service handle its DBus requests on. Unlike in the
  // real cicerone, we can't use the main thread for DBus requests because the
  // unit test itself will be blocking the main thread.
  base::Thread dbus_thread_{"DBus Thread"};
  // The task runner on the dbus thread.
  scoped_refptr<base::SingleThreadTaskRunner> dbus_task_runner_;

  // This needs to exist for Service to start up & shut down right.
  base::SingleThreadTaskExecutor task_executor_;

  // Mocks
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  scoped_refptr<dbus::MockObjectProxy> mock_vm_applications_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_vm_disk_management_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_vm_sk_forwarding_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_url_handler_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_chunneld_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_crosdns_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_concierge_service_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_shill_manager_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_shadercached_proxy_;

  // Callbacks for dbus. Index is DbusCall value for callback.
  DbusCallback dbus_callbacks_[kNumDbusCalls];

  // Temporary directory for TestGuestMetrics.
  base::ScopedTempDir metrics_temp_dir_;

  // The object under test
  std::unique_ptr<Service> service_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_SERVICE_TESTING_HELPER_H_
