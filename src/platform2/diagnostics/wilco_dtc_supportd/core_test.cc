// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/property.h>
#include <dbus/wilco_dtc_supportd/dbus-constants.h>
#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"
#include "diagnostics/wilco_dtc_supportd/core.h"
#include "diagnostics/wilco_dtc_supportd/dbus_service.h"
#include "diagnostics/wilco_dtc_supportd/ec_constants.h"
#include "diagnostics/wilco_dtc_supportd/fake_browser.h"
#include "diagnostics/wilco_dtc_supportd/fake_diagnostics_service.h"
#include "diagnostics/wilco_dtc_supportd/fake_probe_service.h"
#include "diagnostics/wilco_dtc_supportd/fake_wilco_dtc.h"
#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/mojo_grpc_adapter.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service_factory.h"
#include "diagnostics/wilco_dtc_supportd/service_util.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/fake_bluetooth_event_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/fake_ec_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/fake_powerd_event_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/file_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/protobuf_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/fake_bluetooth_client.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/fake_powerd_adapter.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/mock_debugd_adapter.h"
#include "wilco_dtc_supportd.pb.h"  // NOLINT(build/include_directory)

using testing::_;
using testing::ElementsAreArray;
using testing::Invoke;
using testing::Mock;
using testing::Return;
using testing::SaveArg;
using testing::StrictMock;
using testing::WithArg;

namespace diagnostics {
namespace wilco {
namespace {

// Templates for the gRPC URIs that should be used for testing. "%s" is
// substituted with a temporary directory.
const char kWilcoDtcSupportdGrpcUriTemplate[] =
    "unix:%s/test_wilco_dtc_supportd_socket";
const char kWilcoDtcGrpcUriTemplate[] = "unix:%s/test_wilco_dtc_socket";
const char kUiMessageReceiverWilcoDtcGrpcUriTemplate[] =
    "unix:%s/test_ui_message_receiver_wilco_dtc_socket";

using EcEvent = EcService::EcEvent;
using EcEventReason = EcService::EcEvent::Reason;
using MojoEvent = chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdEvent;
using MojomWilcoDtcSupportdService =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService;
using MojomWilcoDtcSupportdServiceFactory =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory;
using MojomWilcoDtcSupportdWebRequestHttpMethod =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestHttpMethod;
using MojomWilcoDtcSupportdWebRequestStatus =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestStatus;

// Returns a callback that, once called, saves its parameter to |*response| and
// quits |*run_loop|.
template <typename ValueType>
base::RepeatingCallback<void(grpc::Status, std::unique_ptr<ValueType>)>
MakeAsyncResponseWriter(const base::RepeatingClosure& callback,
                        std::unique_ptr<ValueType>* response) {
  return base::BindRepeating(
      [](const base::RepeatingClosure& callback,
         std::unique_ptr<ValueType>* response, grpc::Status status,
         std::unique_ptr<ValueType> received_response) {
        ASSERT_TRUE(received_response);
        ASSERT_FALSE(*response);
        *response = std::move(received_response);
        callback.Run();
      },
      callback, base::Unretained(response));
}

class FakeCoreDelegate : public Core::Delegate {
 public:
  FakeCoreDelegate()
      : passed_bluetooth_client_(std::make_unique<FakeBluetoothClient>()),
        passed_debugd_adapter_(
            std::make_unique<StrictMock<MockDebugdAdapter>>()),
        passed_powerd_adapter_(std::make_unique<FakePowerdAdapter>()),
        passed_bluetooth_event_service_(
            std::make_unique<FakeBluetoothEventService>()),
        passed_ec_service_(std::make_unique<FakeEcService>()),
        passed_powerd_event_service_(
            std::make_unique<FakePowerdEventService>()),
        passed_probe_service_(std::make_unique<FakeProbeService>()),
        bluetooth_client_(passed_bluetooth_client_.get()),
        debugd_adapter_(passed_debugd_adapter_.get()),
        powerd_adapter_(passed_powerd_adapter_.get()),
        bluetooth_event_service_(passed_bluetooth_event_service_.get()),
        ec_service_(passed_ec_service_.get()),
        powerd_event_service_(passed_powerd_event_service_.get()),
        probe_service_(passed_probe_service_.get()) {}

  // Must be called no more than once.
  std::unique_ptr<BluetoothClient> CreateBluetoothClient(
      const scoped_refptr<dbus::Bus>& bus) override {
    DCHECK(bus);
    DCHECK(passed_bluetooth_client_);
    return std::move(passed_bluetooth_client_);
  }

  // Must be called no more than once.
  std::unique_ptr<DebugdAdapter> CreateDebugdAdapter(
      const scoped_refptr<dbus::Bus>& bus) override {
    DCHECK(bus);
    DCHECK(passed_debugd_adapter_);
    return std::move(passed_debugd_adapter_);
  }

  // Must be called no more than once.
  std::unique_ptr<PowerdAdapter> CreatePowerdAdapter(
      const scoped_refptr<dbus::Bus>& bus) override {
    DCHECK(bus);
    DCHECK(passed_powerd_adapter_);
    return std::move(passed_powerd_adapter_);
  }

  // Must be called no more than once.
  std::unique_ptr<BluetoothEventService> CreateBluetoothEventService(
      BluetoothClient* bluetooth_client) override {
    DCHECK(bluetooth_client);
    DCHECK(passed_bluetooth_event_service_);
    DCHECK_EQ(bluetooth_client, bluetooth_client_);
    return std::move(passed_bluetooth_event_service_);
  }

  // Must be called no more than once.
  std::unique_ptr<EcService> CreateEcService() override {
    DCHECK(passed_ec_service_);
    return std::move(passed_ec_service_);
  }

  // Must be called no more than once.
  std::unique_ptr<PowerdEventService> CreatePowerdEventService(
      PowerdAdapter* powerd_adapter) override {
    DCHECK(powerd_adapter);
    DCHECK(passed_powerd_event_service_);
    DCHECK_EQ(powerd_adapter, powerd_adapter_);
    return std::move(passed_powerd_event_service_);
  }

  // Must be called no more than once.
  std::unique_ptr<ProbeService> CreateProbeService(
      ProbeService::Delegate* delegate) override {
    DCHECK(delegate);
    DCHECK(passed_probe_service_);
    return std::move(passed_probe_service_);
  }

  StrictMock<MockDebugdAdapter>* debugd_adapter() const {
    return debugd_adapter_;
  }

  FakeBluetoothEventService* bluetooth_event_service() const {
    return bluetooth_event_service_;
  }

  FakeEcService* ec_service() const { return ec_service_; }

  FakePowerdEventService* powerd_event_service() const {
    return powerd_event_service_;
  }

  FakeProbeService* probe_service() const { return probe_service_; }

 private:
  // Mock objects to be transferred by Create* methods.
  std::unique_ptr<FakeBluetoothClient> passed_bluetooth_client_;
  std::unique_ptr<StrictMock<MockDebugdAdapter>> passed_debugd_adapter_;
  std::unique_ptr<FakePowerdAdapter> passed_powerd_adapter_;

  std::unique_ptr<FakeBluetoothEventService> passed_bluetooth_event_service_;
  std::unique_ptr<FakeEcService> passed_ec_service_;
  std::unique_ptr<FakePowerdEventService> passed_powerd_event_service_;
  std::unique_ptr<FakeProbeService> passed_probe_service_;

  // Pointers to objects originally stored in |passed_*| members. These allow
  // continued access by tests even after the corresponding Create* method has
  // been called and ownership has been transferred to |core_|.
  FakeBluetoothClient* bluetooth_client_;
  StrictMock<MockDebugdAdapter>* debugd_adapter_;
  FakePowerdAdapter* powerd_adapter_;

  FakeBluetoothEventService* bluetooth_event_service_;
  FakeEcService* ec_service_;
  FakePowerdEventService* powerd_event_service_;
  FakeProbeService* probe_service_;
};

// Matches gRPC Bluetooth AdapterData and BluetoothEventService AdapterData.
MATCHER_P(BluetoothAdaptersEquals, expected_adapters, "") {
  if (arg.adapters_size() != expected_adapters.size()) {
    return false;
  }
  for (int i = 0; i < arg.adapters_size(); i++) {
    auto expected_carrier_status =
        (expected_adapters[i].powered)
            ? grpc_api::HandleBluetoothDataChangedRequest::AdapterData::
                  STATUS_UP
            : grpc_api::HandleBluetoothDataChangedRequest::AdapterData::
                  STATUS_DOWN;

    const auto& adapter = arg.adapters(i);

    if (adapter.adapter_name() != expected_adapters[i].name ||
        adapter.adapter_mac_address() != expected_adapters[i].address ||
        adapter.carrier_status() != expected_carrier_status ||
        adapter.connected_devices_count() !=
            expected_adapters[i].connected_devices_count) {
      return false;
    }
  }
  return true;
}

class MockDaemon {
 public:
  MOCK_METHOD(void, ShutDown, ());
};

// Tests for the Core class.
class CoreTest : public testing::Test {
 protected:
  void CreateCore(const std::vector<std::string>& grpc_service_uris) {
    core_ = std::make_unique<Core>(&core_delegate_, grpc_client_manager(),
                                   grpc_service_uris, &mojo_service_factory_);
  }

  Core* core() {
    DCHECK(core_);
    return core_.get();
  }

  FakeCoreDelegate* core_delegate() { return &core_delegate_; }

  // Fake for MojoServiceFactory::BindFactoryCallback that simulates
  // successful Mojo service receiver to the given file descriptor. After the
  // mock gets triggered, |mojo_service_factory_remote_| becomes
  // initialized to point to the tested Mojo service.
  // If |simulate_bind_failure_| is true, |mojo_service_factory_remote_| will
  // not be bound and fail the is_bound() check in MojoServiceFactory::Start.
  void FakeBindMojoFactory(MojoServiceFactory::MojoReceiver* receiver,
                           base::ScopedFD mojo_pipe_fd) {
    if (simulate_bind_failure_)
      return;
    // Initialize a Mojo receiver that, instead of working through the
    // given (fake) file descriptor, talks to the test endpoint
    // |mojo_service_|.
    receiver->Bind(mojo_service_factory_remote_.BindNewPipeAndPassReceiver());
    DCHECK(mojo_service_factory_remote_);
  }

  GrpcClientManager* grpc_client_manager() { return &grpc_client_manager_; }

  StrictMock<MockDaemon>* daemon() { return &daemon_; }

  MojoServiceFactory* mojo_service_factory() { return &mojo_service_factory_; }

  mojo::Remote<MojomWilcoDtcSupportdServiceFactory>*
  mojo_service_factory_remote() {
    return &mojo_service_factory_remote_;
  }

  void SimulateBindFailure() { simulate_bind_failure_ = true; }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};

  GrpcClientManager grpc_client_manager_;
  MojoGrpcAdapter mojo_grpc_adapter_{&grpc_client_manager_};

  // Mocked daemon (for calling ShutDown()).
  StrictMock<MockDaemon> daemon_;

  // Mojo interface to the service factory exposed by the tested code.
  mojo::Remote<MojomWilcoDtcSupportdServiceFactory>
      mojo_service_factory_remote_;

  MojoServiceFactory mojo_service_factory_{
      &mojo_grpc_adapter_,
      base::BindRepeating(&StrictMock<MockDaemon>::ShutDown,
                          base::Unretained(&daemon_)),
      base::BindOnce(&CoreTest::FakeBindMojoFactory, base::Unretained(this))};

  bool simulate_bind_failure_ = false;

  StrictMock<FakeCoreDelegate> core_delegate_;

  std::unique_ptr<Core> core_;
};

// Test successful shutdown after failed start.
TEST_F(CoreTest, FailedStartAndSuccessfulShutdown) {
  // Invalid gRPC service URI.
  CreateCore({""});
  EXPECT_FALSE(core()->Start());

  ShutDownServicesInRunLoop(core());
}

// Tests for the Core class which started successfully.
class StartedCoreTest : public CoreTest {
 protected:
  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(CoreTest::SetUp());

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    wilco_dtc_supportd_grpc_uri_ = base::StringPrintf(
        kWilcoDtcSupportdGrpcUriTemplate, temp_dir_.GetPath().value().c_str());
    ui_message_receiver_wilco_dtc_grpc_uri_ =
        base::StringPrintf(kUiMessageReceiverWilcoDtcGrpcUriTemplate,
                           temp_dir_.GetPath().value().c_str());

    wilco_dtc_grpc_uri_ = base::StringPrintf(
        kWilcoDtcGrpcUriTemplate, temp_dir_.GetPath().value().c_str());

    CreateCore({wilco_dtc_supportd_grpc_uri_});
    core()->set_root_dir_for_testing(temp_dir_.GetPath());

    SetUpEcService();

    ASSERT_TRUE(core()->Start());
    grpc_client_manager()->Start(ui_message_receiver_wilco_dtc_grpc_uri_,
                                 {wilco_dtc_grpc_uri_});

    SetUpEcServiceFifoWriteEnd();

    SetUpDBus();

    fake_browser_ = std::make_unique<FakeBrowser>(
        mojo_service_factory_remote(), bootstrap_mojo_connection_dbus_method_);
  }

  void TearDown() override {
    SetDBusShutdownExpectations();

    dbus_service_.ShutDown();

    ShutDownServicesInRunLoop(core(), grpc_client_manager());

    CoreTest::TearDown();
  }

  const base::FilePath& temp_dir_path() const {
    DCHECK(temp_dir_.IsValid());
    return temp_dir_.GetPath();
  }

  FakeBrowser* fake_browser() {
    DCHECK(fake_browser_);
    return fake_browser_.get();
  }

  dbus::ExportedObject::MethodCallCallback
  bootstrap_mojo_connection_dbus_method() {
    return bootstrap_mojo_connection_dbus_method_;
  }

  const std::string& wilco_dtc_supportd_grpc_uri() const {
    DCHECK(!wilco_dtc_supportd_grpc_uri_.empty());
    return wilco_dtc_supportd_grpc_uri_;
  }

  const std::string& ui_message_receiver_wilco_dtc_grpc_uri() const {
    DCHECK(!ui_message_receiver_wilco_dtc_grpc_uri_.empty());
    return ui_message_receiver_wilco_dtc_grpc_uri_;
  }

  const std::string& wilco_dtc_grpc_uri() const {
    DCHECK(!wilco_dtc_grpc_uri_.empty());
    return wilco_dtc_grpc_uri_;
  }

  void BootstrapMojoConnection(FakeMojoFdGenerator* fake_mojo_fd_generator) {
    base::RunLoop run_loop;
    ASSERT_TRUE(fake_browser()->BootstrapMojoConnection(
        fake_mojo_fd_generator, run_loop.QuitClosure()));
    run_loop.Run();
  }

 private:
  // Perform initialization of the D-Bus object exposed by the tested code.
  void SetUpDBus() {
    const dbus::ObjectPath kDBusObjectPath(kWilcoDtcSupportdServicePath);

    // Expect that the /org/chromium/WilcoDtcSupportd object is exported.
    wilco_dtc_supportd_dbus_object_ = new StrictMock<dbus::MockExportedObject>(
        dbus_bus_.get(), kDBusObjectPath);
    EXPECT_CALL(*dbus_bus_, GetExportedObject(kDBusObjectPath))
        .WillOnce(Return(wilco_dtc_supportd_dbus_object_.get()));

    // Expect that standard methods on the org.freedesktop.DBus.Properties
    // interface are exported.
    EXPECT_CALL(
        *wilco_dtc_supportd_dbus_object_,
        ExportMethod(dbus::kPropertiesInterface, dbus::kPropertiesGet, _, _));
    EXPECT_CALL(
        *wilco_dtc_supportd_dbus_object_,
        ExportMethod(dbus::kPropertiesInterface, dbus::kPropertiesSet, _, _));
    EXPECT_CALL(*wilco_dtc_supportd_dbus_object_,
                ExportMethod(dbus::kPropertiesInterface,
                             dbus::kPropertiesGetAll, _, _));

    // Expect that methods on the org.chromium.WilcoDtcSupportdInterface
    // interface are exported.
    EXPECT_CALL(
        *wilco_dtc_supportd_dbus_object_,
        ExportMethod(kWilcoDtcSupportdServiceInterface,
                     kWilcoDtcSupportdBootstrapMojoConnectionMethod, _, _))
        .WillOnce(Invoke(this, &StartedCoreTest::MockExportMethod));

    // Run the tested code that exports D-Bus objects and methods.
    scoped_refptr<brillo::dbus_utils::AsyncEventSequencer> dbus_sequencer(
        new brillo::dbus_utils::AsyncEventSequencer());
    dbus_service_.RegisterDBusObjectsAsync(dbus_bus_, dbus_sequencer.get());
    core()->CreateDbusAdapters(dbus_bus_);

    // Verify that required D-Bus methods are exported.
    EXPECT_FALSE(bootstrap_mojo_connection_dbus_method_.is_null());
  }

  // Mock implementation of the `wilco_dtc_supportd_dbus_object_`'s
  // `ExportMethod()` method.
  void MockExportMethod(
      const std::string& interface_name,
      const std::string& method_name,
      dbus::ExportedObject::MethodCallCallback method_callback,
      dbus::ExportedObject::OnExportedCallback on_exported_callback) {
    DCHECK(interface_name == kWilcoDtcSupportdServiceInterface);
    DCHECK(method_name == kWilcoDtcSupportdBootstrapMojoConnectionMethod);
    bootstrap_mojo_connection_dbus_method_ = method_callback;
  }

  // Set mock expectations for calls triggered during test destruction.
  void SetDBusShutdownExpectations() {
    EXPECT_CALL(*wilco_dtc_supportd_dbus_object_, Unregister());
  }

  // Creates FIFO to emulates the EC event file used by EC event service.
  void SetUpEcService() {
    core_delegate()->ec_service()->set_event_fd_events_for_testing(POLLIN);
    ASSERT_TRUE(base::CreateDirectory(ec_event_file_path().DirName()));
    ASSERT_EQ(mkfifo(ec_event_file_path().value().c_str(), 0600), 0);
  }

  // Setups |ec_service_fd_| FIFO file descriptor. Must be called only
  // after |Core::Start()| call. Otherwise, it will block
  // thread.
  void SetUpEcServiceFifoWriteEnd() {
    ASSERT_FALSE(ec_service_fd_.is_valid());
    ec_service_fd_.reset(open(ec_event_file_path().value().c_str(), O_WRONLY));
    ASSERT_TRUE(ec_service_fd_.is_valid());
  }

  base::FilePath ec_event_file_path() const {
    return temp_dir_.GetPath().Append(kEcEventFilePath);
  }

  base::ScopedTempDir temp_dir_;

  // gRPC URI on which the tested "WilcoDtcSupportd" gRPC service (owned by
  // Core) is listening.
  std::string wilco_dtc_supportd_grpc_uri_;
  // gRPC URI on which the fake "WilcoDtc" gRPC service (owned by FakeWilcoDtc)
  // is listening, eligible to receive UI messages.
  std::string ui_message_receiver_wilco_dtc_grpc_uri_;
  // gRPC URI on which the fake "WilcoDtc" gRPC service (owned by FakeWilcoDtc)
  // is listening.
  std::string wilco_dtc_grpc_uri_;

  scoped_refptr<StrictMock<dbus::MockBus>> dbus_bus_ =
      new StrictMock<dbus::MockBus>(dbus::Bus::Options());

  DBusService dbus_service_{mojo_service_factory()};

  // Mock D-Bus integration helper for the object exposed by the tested code.
  scoped_refptr<StrictMock<dbus::MockExportedObject>>
      wilco_dtc_supportd_dbus_object_;

  // Write end of FIFO that emulates EC event file. EC service operates with
  // read end of FIFO as with usual file. Must be initialized only after
  // |Core::Start()| call.
  base::ScopedFD ec_service_fd_;

  // Callback that the tested code exposed as the BootstrapMojoConnection D-Bus
  // method.
  dbus::ExportedObject::MethodCallCallback
      bootstrap_mojo_connection_dbus_method_;

  std::unique_ptr<FakeBrowser> fake_browser_;
};

// Test that the Mojo service gets successfully bootstrapped after the
// BootstrapMojoConnection D-Bus method is called.
TEST_F(StartedCoreTest, MojoBootstrapSuccess) {
  FakeMojoFdGenerator fake_mojo_fd_generator;
  BootstrapMojoConnection(&fake_mojo_fd_generator);
  EXPECT_TRUE(*mojo_service_factory_remote());
}

// Test failure to bootstrap the Mojo service due to an error returned by
// MojoServiceFactory::BootstrapMojoConnection().
TEST_F(StartedCoreTest, MojoBootstrapErrorToBind) {
  FakeMojoFdGenerator fake_mojo_fd_generator;
  EXPECT_CALL(*daemon(), ShutDown());

  SimulateBindFailure();

  base::RunLoop run_loop;
  EXPECT_FALSE(fake_browser()->BootstrapMojoConnection(&fake_mojo_fd_generator,
                                                       run_loop.QuitClosure()));
  run_loop.Run();
}

// Test that second attempt to bootstrap the Mojo service results in error and
// the daemon shutdown.
TEST_F(StartedCoreTest, MojoBootstrapErrorRepeated) {
  FakeMojoFdGenerator first_fake_mojo_fd_generator;
  BootstrapMojoConnection(&first_fake_mojo_fd_generator);

  FakeMojoFdGenerator second_fake_mojo_fd_generator;
  EXPECT_CALL(*daemon(), ShutDown());

  base::RunLoop run_loop;
  EXPECT_FALSE(fake_browser()->BootstrapMojoConnection(
      &second_fake_mojo_fd_generator, run_loop.QuitClosure()));
  run_loop.Run();
}

// Test that the daemon gets shut down when the previously bootstrapped Mojo
// connection aborts.
TEST_F(StartedCoreTest, MojoBootstrapSuccessThenAbort) {
  FakeMojoFdGenerator fake_mojo_fd_generator;
  BootstrapMojoConnection(&fake_mojo_fd_generator);

  EXPECT_CALL(*daemon(), ShutDown());

  // Abort the Mojo connection by closing the browser-side endpoint.
  mojo_service_factory_remote()->reset();
  base::RunLoop().RunUntilIdle();
}

// Test that the method |ProbeTelemetryInfo()| calls into
// ProbeService
TEST_F(StartedCoreTest, ProbeTelemetryInfo) {
  using ProbeTelemetryInfoCallback =
      base::OnceCallback<void(ash::cros_healthd::mojom::TelemetryInfoPtr)>;
  const auto kCategories =
      std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>{
          ash::cros_healthd::mojom::ProbeCategoryEnum::kFan,
          ash::cros_healthd::mojom::ProbeCategoryEnum::kCpu,
          ash::cros_healthd::mojom::ProbeCategoryEnum::kStatefulPartition};

  core_delegate()->probe_service()->SetProbeTelemetryInfoCallback(
      base::BindOnce(
          [](std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>
                 expected_categories,
             std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum>
                 received_categories,
             ProbeTelemetryInfoCallback received_callback) {
            EXPECT_EQ(expected_categories, received_categories);
            std::move(received_callback).Run(nullptr);
          },
          kCategories));

  base::RunLoop run_loop;
  static_cast<GrpcService::Delegate*>(core())->ProbeTelemetryInfo(
      kCategories, base::BindOnce(
                       [](base::OnceClosure loop_closure,
                          ash::cros_healthd::mojom::TelemetryInfoPtr) {
                         std::move(loop_closure).Run();
                       },
                       run_loop.QuitClosure()));
  run_loop.Run();
}

// Test that the method |RequestBluetoothDataNotification()| exposed by
// wilco_dtc_supportd gRPC calls clients with the updated data
TEST_F(StartedCoreTest, HandleRequestBluetoothDataNotification) {
  std::vector<BluetoothEventService::AdapterData> adapters(2);
  adapters[0].name = "sarien-laptop";
  adapters[0].address = "aa:bb:cc:dd:ee:ff";
  adapters[0].powered = true;
  adapters[0].connected_devices_count = 0;
  adapters[1].name = "usb-bluetooth";
  adapters[1].address = "00:11:22:33:44:55";
  adapters[1].powered = false;
  adapters[1].connected_devices_count = 2;

  FakeWilcoDtc fake_wilco_dtc(wilco_dtc_grpc_uri(),
                              wilco_dtc_supportd_grpc_uri());
  FakeWilcoDtc fake_ui_message_receiver_wilco_dtc(
      ui_message_receiver_wilco_dtc_grpc_uri(), wilco_dtc_supportd_grpc_uri());

  {
    base::RunLoop run_loop;
    auto barrier_closure = base::BarrierClosure(2, run_loop.QuitClosure());

    auto update_callback = base::BindRepeating(
        [](const base::RepeatingClosure& callback,
           const grpc_api::HandleBluetoothDataChangedRequest&) {
          callback.Run();
        },
        barrier_closure);

    fake_wilco_dtc.set_bluetooth_data_changed_callback(update_callback);
    fake_ui_message_receiver_wilco_dtc.set_bluetooth_data_changed_callback(
        update_callback);

    core_delegate()->bluetooth_event_service()->EmitBluetoothAdapterDataChanged(
        adapters);

    run_loop.Run();
  }

  {
    auto bluetooth_callback =
        [](const base::RepeatingClosure& callback,
           grpc_api::HandleBluetoothDataChangedRequest* request_out,
           const grpc_api::HandleBluetoothDataChangedRequest& request) {
          DCHECK(request_out);
          *request_out = request;
          callback.Run();
        };

    base::RunLoop run_loop;
    auto barrier_closure = base::BarrierClosure(3, run_loop.QuitClosure());

    grpc_api::HandleBluetoothDataChangedRequest
        fake_wilco_dtc_bluetooth_grpc_request;
    grpc_api::HandleBluetoothDataChangedRequest
        fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request;
    fake_wilco_dtc.set_bluetooth_data_changed_callback(
        base::BindRepeating(bluetooth_callback, barrier_closure,
                            &fake_wilco_dtc_bluetooth_grpc_request));
    fake_ui_message_receiver_wilco_dtc.set_bluetooth_data_changed_callback(
        base::BindRepeating(
            bluetooth_callback, barrier_closure,
            &fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request));

    fake_wilco_dtc.RequestBluetoothDataNotification(
        grpc_api::RequestBluetoothDataNotificationRequest{},
        base::BindRepeating(
            [](base::RepeatingClosure barrier_closure, grpc::Status status,
               std::unique_ptr<
                   grpc_api::RequestBluetoothDataNotificationResponse>) {
              barrier_closure.Run();
            },
            barrier_closure));

    run_loop.Run();

    EXPECT_THAT(fake_wilco_dtc_bluetooth_grpc_request,
                BluetoothAdaptersEquals(adapters));
    EXPECT_THAT(fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request,
                BluetoothAdaptersEquals(adapters));
  }
}

// Tests for the Core class with the already established Mojo
// connection to the fake browser and gRPC communication with the fake
// wilco_dtc.
class BootstrappedCoreTest : public StartedCoreTest {
 protected:
  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(StartedCoreTest::SetUp());

    FakeMojoFdGenerator fake_mojo_fd_generator;
    BootstrapMojoConnection(&fake_mojo_fd_generator);

    ASSERT_TRUE(*mojo_service_factory_remote());

    fake_wilco_dtc_ = std::make_unique<FakeWilcoDtc>(
        wilco_dtc_grpc_uri(), wilco_dtc_supportd_grpc_uri());

    fake_ui_message_receiver_wilco_dtc_ =
        std::make_unique<FakeWilcoDtc>(ui_message_receiver_wilco_dtc_grpc_uri(),
                                       wilco_dtc_supportd_grpc_uri());
  }

  void TearDown() override {
    fake_wilco_dtc_.reset();
    fake_ui_message_receiver_wilco_dtc_.reset();
    StartedCoreTest::TearDown();
  }

  FakeWilcoDtc* fake_ui_message_receiver_wilco_dtc() {
    return fake_ui_message_receiver_wilco_dtc_.get();
  }

  FakeWilcoDtc* fake_wilco_dtc() { return fake_wilco_dtc_.get(); }

  base::OnceCallback<void(mojo::ScopedHandle)>
  fake_browser_valid_handle_callback(
      const base::RepeatingClosure& callback,
      const std::string& expected_response_json_message) {
    return base::BindOnce(
        [](base::OnceClosure callback,
           const std::string& expected_response_json_message,
           mojo::ScopedHandle response_json_message_handle) {
          auto shm_mapping = GetReadOnlySharedMemoryMappingFromMojoHandle(
              std::move(response_json_message_handle));
          ASSERT_TRUE(shm_mapping.IsValid());
          ASSERT_EQ(expected_response_json_message,
                    std::string(shm_mapping.GetMemoryAs<const char>(),
                                shm_mapping.mapped_size()));
          std::move(callback).Run();
        },
        callback, expected_response_json_message);
  }

  base::OnceCallback<void(mojo::ScopedHandle)>
  fake_browser_invalid_handle_callback(const base::RepeatingClosure& callback) {
    return base::BindOnce(
        [](base::OnceClosure callback,
           mojo::ScopedHandle response_json_message_handle) {
          ASSERT_FALSE(response_json_message_handle.is_valid());
          std::move(callback).Run();
        },
        callback);
  }

  MockMojoClient* wilco_dtc_supportd_client() {
    return fake_browser()->wilco_dtc_supportd_client();
  }

 private:
  std::unique_ptr<FakeWilcoDtc> fake_ui_message_receiver_wilco_dtc_;
  std::unique_ptr<FakeWilcoDtc> fake_wilco_dtc_;
};

// Test that the UI message receiver wilco_dtc will receive message from
// browser.
TEST_F(BootstrappedCoreTest, SendGrpcUiMessageToWilcoDtc) {
  constexpr char kJsonMessageRequest[] = "{\"message\": \"ping\"}";
  constexpr char kJsonMessageResponse[] = "{\"message\": \"pong\"}";

  base::RunLoop run_loop;
  const auto barrier_closure = base::BarrierClosure(2, run_loop.QuitClosure());

  fake_ui_message_receiver_wilco_dtc()->set_handle_message_from_ui_callback(
      barrier_closure);
  fake_ui_message_receiver_wilco_dtc()
      ->set_handle_message_from_ui_json_message_response(kJsonMessageResponse);
  fake_wilco_dtc()->set_handle_message_from_ui_callback(base::BindOnce([]() {
    // The wilco_dtc not eligible to receive messages from UI must not
    // receive them.
    FAIL();
  }));

  auto callback =
      fake_browser_valid_handle_callback(barrier_closure, kJsonMessageResponse);
  EXPECT_TRUE(fake_browser()->SendUiMessageToWilcoDtc(kJsonMessageRequest,
                                                      std::move(callback)));

  run_loop.Run();

  EXPECT_EQ(kJsonMessageRequest,
            fake_ui_message_receiver_wilco_dtc()
                ->handle_message_from_ui_actual_json_message());
}

// Test that the UI message receiver wilco_dtc will not receive message from
// browser if JSON message is invalid.
TEST_F(BootstrappedCoreTest, SendGrpcUiMessageToWilcoDtcInvalidJSON) {
  constexpr char kJsonMessage[] = "{'some_key': 'some_value'}";

  base::RunLoop run_loop_fake_browser;

  auto callback =
      fake_browser_invalid_handle_callback(run_loop_fake_browser.QuitClosure());
  EXPECT_TRUE(fake_browser()->SendUiMessageToWilcoDtc(kJsonMessage,
                                                      std::move(callback)));

  run_loop_fake_browser.Run();
  // There's no reliable way to wait till the wrong HandleMessageFromUi(), if
  // the tested code is buggy and calls it, gets executed. The RunUntilIdle() is
  // used to make the test failing at least with some probability in case of
  // such a bug.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(fake_ui_message_receiver_wilco_dtc()
                   ->handle_message_from_ui_actual_json_message()
                   .has_value());
}

// Test that the UI message receiver wilco_dtc will receive message from
// browser.
TEST_F(BootstrappedCoreTest, SendGrpcUiMessageToWilcoDtcInvalidResponseJSON) {
  constexpr char kJsonMessageRequest[] = "{\"some_key\": \"some_value\"}";
  constexpr char kJsonMessageResponse[] = "{'key': 'value'}";

  base::RunLoop run_loop;
  const auto barrier_closure = base::BarrierClosure(2, run_loop.QuitClosure());

  fake_ui_message_receiver_wilco_dtc()->set_handle_message_from_ui_callback(
      barrier_closure);
  fake_ui_message_receiver_wilco_dtc()
      ->set_handle_message_from_ui_json_message_response(kJsonMessageResponse);

  EXPECT_TRUE(fake_browser()->SendUiMessageToWilcoDtc(
      kJsonMessageRequest,
      fake_browser_invalid_handle_callback(barrier_closure)));

  run_loop.Run();

  EXPECT_EQ(kJsonMessageRequest,
            fake_ui_message_receiver_wilco_dtc()
                ->handle_message_from_ui_actual_json_message());
}

// Test that wilco_dtc_supportd can get a CrosHealthdDiagnosticsServicePtr from
// the browser and use it to fulfill a request from wilco_dtc.
TEST_F(BootstrappedCoreTest, GetCrosHealthdDiagnosticsService) {
  FakeDiagnosticsService fake_diagnostics_service;
  EXPECT_CALL(*wilco_dtc_supportd_client(), GetCrosHealthdDiagnosticsService(_))
      .WillOnce(WithArg<0>(
          [&](mojo::PendingReceiver<
              ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
                  service) {
            fake_diagnostics_service.GetCrosHealthdDiagnosticsService(
                std::move(service));
          }));
  fake_diagnostics_service.SetGetAvailableRoutinesResponse(
      std::vector<ash::cros_healthd::mojom::DiagnosticRoutineEnum>{
          ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBatteryCapacity});

  std::vector<grpc_api::DiagnosticRoutine> received_routines;
  base::RunLoop run_loop;
  fake_wilco_dtc()->GetAvailableRoutines(base::BindRepeating(
      [](base::RepeatingClosure quit_closure,
         std::vector<grpc_api::DiagnosticRoutine>* unpacked_response_out,
         grpc::Status status,
         std::unique_ptr<grpc_api::GetAvailableRoutinesResponse> response) {
        for (int i = 0; i < response->routines_size(); i++)
          unpacked_response_out->push_back(response->routines(i));
        quit_closure.Run();
      },
      run_loop.QuitClosure(), &received_routines));
  run_loop.Run();

  EXPECT_THAT(received_routines, ElementsAreArray({grpc_api::ROUTINE_BATTERY}));
}

// Test that wilco_dtc will be notified about configuration changes from
// browser.
TEST_F(BootstrappedCoreTest, NotifyConfigurationDataChanged) {
  base::RunLoop run_loop;
  const base::RepeatingClosure barrier_closure =
      base::BarrierClosure(2, run_loop.QuitClosure());

  fake_ui_message_receiver_wilco_dtc()->set_configuration_data_changed_callback(
      barrier_closure);
  fake_wilco_dtc()->set_configuration_data_changed_callback(barrier_closure);

  fake_browser()->NotifyConfigurationDataChanged();
  run_loop.Run();
}

// Test that a message can be sent from wilco_dtc to browser and
// returns an expected response
TEST_F(BootstrappedCoreTest, SendWilcoDtcMessageToUi) {
  constexpr char kFakeMessageToUi[] = "{\"message\": \"Fake JSON to UI\"}";
  constexpr char kFakeMessageFromUi[] = "{\"message\": \"Fake JSON from UI\"}";
  EXPECT_CALL(*wilco_dtc_supportd_client(),
              SendWilcoDtcMessageToUiImpl(kFakeMessageToUi, _))
      .WillOnce(WithArg<1>(
          Invoke([kFakeMessageFromUi](
                     base::OnceCallback<void(mojo::ScopedHandle)> callback) {
            std::move(callback).Run(
                CreateReadOnlySharedMemoryRegionMojoHandle(kFakeMessageFromUi));
          })));

  std::unique_ptr<grpc_api::SendMessageToUiResponse> response;
  {
    base::RunLoop run_loop;
    grpc_api::SendMessageToUiRequest request;
    request.set_json_message(kFakeMessageToUi);
    fake_wilco_dtc()->SendMessageToUi(
        request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
    run_loop.Run();
  }

  ASSERT_TRUE(response);
  grpc_api::SendMessageToUiResponse expected_response;
  expected_response.set_response_json_message(kFakeMessageFromUi);
  EXPECT_THAT(*response, ProtobufEquals(expected_response))
      << "Actual: {" << response->ShortDebugString() << "}";
}

// Test that the GetProcData() method exposed by the daemon's gRPC server
// returns a dump of the corresponding file from the disk.
TEST_F(BootstrappedCoreTest, GetProcDataGrpcCall) {
  constexpr char kFakeFileContents[] = "foo";
  const base::FilePath file_path = temp_dir_path().Append("proc/uptime");
  ASSERT_TRUE(WriteFileAndCreateParentDirs(file_path, kFakeFileContents));

  grpc_api::GetProcDataRequest request;
  request.set_type(grpc_api::GetProcDataRequest::FILE_UPTIME);
  std::unique_ptr<grpc_api::GetProcDataResponse> response;
  base::RunLoop run_loop;
  fake_wilco_dtc()->GetProcData(
      request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
  run_loop.Run();

  ASSERT_TRUE(response);
  grpc_api::GetProcDataResponse expected_response;
  expected_response.add_file_dump();
  expected_response.mutable_file_dump(0)->set_path(file_path.value());
  expected_response.mutable_file_dump(0)->set_canonical_path(file_path.value());
  expected_response.mutable_file_dump(0)->set_contents(kFakeFileContents);
  EXPECT_TRUE(google::protobuf::util::MessageDifferencer::Equals(
      *response, expected_response))
      << "Obtained: " << response->ShortDebugString()
      << ",\nExpected: " << expected_response.ShortDebugString();
}

// Test that the GetEcTelemetry() method exposed by the daemon's gRPC server
// writes payload to devfs file exposed by the EC driver and reads response
// using the same file.
TEST_F(BootstrappedCoreTest, GetEcTelemetryGrpcCall) {
  const base::FilePath kFilePath =
      temp_dir_path().Append(kEcGetTelemetryFilePath);
  const std::string kRequestPayload = "12345";
  const std::string kResponsePayload = "67890";

  // Write request and response payload because EC telemetry char device is
  // non-seekable.
  ASSERT_TRUE(WriteFileAndCreateParentDirs(kFilePath,
                                           kRequestPayload + kResponsePayload));

  grpc_api::GetEcTelemetryRequest request;
  request.set_payload(kRequestPayload);
  std::unique_ptr<grpc_api::GetEcTelemetryResponse> response;
  base::RunLoop run_loop;
  fake_wilco_dtc()->GetEcTelemetry(
      request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
  run_loop.Run();

  ASSERT_TRUE(response);
  grpc_api::GetEcTelemetryResponse expected_response;
  expected_response.set_status(grpc_api::GetEcTelemetryResponse::STATUS_OK);
  expected_response.set_payload(kResponsePayload);
  EXPECT_THAT(*response, ProtobufEquals(expected_response))
      << "Actual: {" << response->ShortDebugString() << "}";
}

// Test that PerformWebRequest() method exposed by the daemon's gRPC returns a
// Web request response from the browser.
TEST_F(BootstrappedCoreTest, PerformWebRequestToBrowser) {
  constexpr char kHttpsUrl[] = "https://www.google.com";
  constexpr char kHeader1[] = "Accept-Language: en-US";
  constexpr char kHeader2[] = "Accept: text/html";
  constexpr char kBodyRequest[] = "<html>Request</html>";

  constexpr int kHttpStatusOk = 200;
  constexpr char kBodyResponse[] = "<html>Response</html>";

  grpc_api::PerformWebRequestParameter request;
  request.set_http_method(
      grpc_api::PerformWebRequestParameter::HTTP_METHOD_POST);
  request.set_url(kHttpsUrl);
  request.set_request_body(kBodyRequest);
  *request.add_headers() = kHeader1;
  *request.add_headers() = kHeader2;

  std::unique_ptr<grpc_api::PerformWebRequestResponse> response;
  {
    base::RunLoop run_loop;
    EXPECT_CALL(
        *fake_browser()->wilco_dtc_supportd_client(),
        PerformWebRequestImpl(
            MojomWilcoDtcSupportdWebRequestHttpMethod::kPost, kHttpsUrl,
            std::vector<std::string>{kHeader1, kHeader2}, kBodyRequest, _))
        .WillOnce(WithArg<4>(
            Invoke([kBodyResponse](
                       MockMojoClient::MojoPerformWebRequestCallback callback) {
              std::move(callback).Run(
                  MojomWilcoDtcSupportdWebRequestStatus::kOk, kHttpStatusOk,
                  CreateReadOnlySharedMemoryRegionMojoHandle(kBodyResponse));
            })));
    fake_wilco_dtc()->PerformWebRequest(
        request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
    run_loop.Run();
  }

  ASSERT_TRUE(response);
  grpc_api::PerformWebRequestResponse expected_response;
  expected_response.set_status(grpc_api::PerformWebRequestResponse::STATUS_OK);
  expected_response.set_http_status(kHttpStatusOk);
  expected_response.set_response_body(kBodyResponse);
  EXPECT_THAT(*response, ProtobufEquals(expected_response))
      << "Actual: {" << response->ShortDebugString() << "}";
}

// Test that GetConfigurationData() method exposed by the daemon's gRPC returns
// a response from the browser.
TEST_F(BootstrappedCoreTest, GetConfigurationDataFromBrowser) {
  constexpr char kFakeJsonConfigurationData[] =
      "{\"fake-message\": \"Fake JSON configuration data\"}";
  EXPECT_CALL(*wilco_dtc_supportd_client(), GetConfigurationData(_))
      .WillOnce(
          Invoke([kFakeJsonConfigurationData](
                     base::OnceCallback<void(const std::string&)> callback) {
            std::move(callback).Run(kFakeJsonConfigurationData);
          }));
  std::unique_ptr<grpc_api::GetConfigurationDataResponse> response;
  {
    base::RunLoop run_loop;
    grpc_api::GetConfigurationDataRequest request;
    fake_wilco_dtc()->GetConfigurationData(
        request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
    run_loop.Run();
  }

  ASSERT_TRUE(response);
  grpc_api::GetConfigurationDataResponse expected_response;
  expected_response.set_json_configuration_data(kFakeJsonConfigurationData);
  EXPECT_THAT(*response, ProtobufEquals(expected_response))
      << "Actual: {" << response->ShortDebugString() << "}";
}

// Test that GetDriveSystemData() method exposed by the daemon's gRPC returns
// a response from the debugd.
TEST_F(BootstrappedCoreTest, GetDriveSystemData) {
  constexpr char kFakeSmartctlData[] = "Fake smartctl data";
  EXPECT_CALL(*core_delegate()->debugd_adapter(), GetSmartAttributes(_))
      .WillOnce(
          WithArg<0>([kFakeSmartctlData](
                         DebugdAdapter::OnceStringResultCallback callback) {
            std::move(callback).Run(kFakeSmartctlData, nullptr);
          }));
  std::unique_ptr<grpc_api::GetDriveSystemDataResponse> response;
  {
    base::RunLoop run_loop;
    grpc_api::GetDriveSystemDataRequest request;
    request.set_type(grpc_api::GetDriveSystemDataRequest::SMART_ATTRIBUTES);
    fake_wilco_dtc()->GetDriveSystemData(
        request, MakeAsyncResponseWriter(run_loop.QuitClosure(), &response));
    run_loop.Run();
  }

  ASSERT_TRUE(response);
  grpc_api::GetDriveSystemDataResponse expected_response;
  expected_response.set_status(grpc_api::GetDriveSystemDataResponse::STATUS_OK);
  expected_response.set_payload(kFakeSmartctlData);
  EXPECT_THAT(*response, ProtobufEquals(expected_response))
      << "Actual: {" << response->ShortDebugString() << "}";
}

// Test that the method |HandleBluetoothDataChanged()| exposed by wilco_dtc gRPC
// is called by wilco_dtc support daemon.
TEST_F(BootstrappedCoreTest, HandleBluetoothDataChanged) {
  std::vector<BluetoothEventService::AdapterData> adapters(2);
  adapters[0].name = "sarien-laptop";
  adapters[0].address = "aa:bb:cc:dd:ee:ff";
  adapters[0].powered = true;
  adapters[0].connected_devices_count = 0;
  adapters[1].name = "usb-bluetooth";
  adapters[1].address = "00:11:22:33:44:55";
  adapters[1].powered = false;
  adapters[1].connected_devices_count = 2;

  auto bluetooth_callback =
      [](const base::RepeatingClosure& callback,
         grpc_api::HandleBluetoothDataChangedRequest* request_out,
         const grpc_api::HandleBluetoothDataChangedRequest& request) {
        DCHECK(request_out);
        *request_out = request;
        callback.Run();
      };

  base::RunLoop run_loop;
  auto barrier_closure = base::BarrierClosure(2, run_loop.QuitClosure());

  grpc_api::HandleBluetoothDataChangedRequest
      fake_wilco_dtc_bluetooth_grpc_request;
  grpc_api::HandleBluetoothDataChangedRequest
      fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request;

  fake_wilco_dtc()->set_bluetooth_data_changed_callback(
      base::BindRepeating(bluetooth_callback, barrier_closure,
                          &fake_wilco_dtc_bluetooth_grpc_request));
  fake_ui_message_receiver_wilco_dtc()->set_bluetooth_data_changed_callback(
      base::BindRepeating(
          bluetooth_callback, barrier_closure,
          &fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request));

  core_delegate()->bluetooth_event_service()->EmitBluetoothAdapterDataChanged(
      adapters);

  run_loop.Run();

  EXPECT_THAT(fake_wilco_dtc_bluetooth_grpc_request,
              BluetoothAdaptersEquals(adapters));
  EXPECT_THAT(fake_ui_message_receiver_wilco_dtc_bluetooth_grpc_request,
              BluetoothAdaptersEquals(adapters));
}

// Tests for EcService::Observer.
//
// This is a parametrized test with the following parameters:
// * |ec_event_reason| - the reason of the EcEvent
// * |expected_mojo_event| - the expected mojo event passed to the
// |wilco_dtc_supportd_client| over mojo
class EcServiceBootstrappedCoreTest
    : public BootstrappedCoreTest,
      public testing::WithParamInterface<
          std::tuple<EcEventReason, std::optional<MojoEvent>>> {
 protected:
  // Holds EC event type and payload of |grpc_api::HandleEcNotificationResponse|
  using GrpcEvent = std::pair<uint16_t, std::string>;

  void EmulateEcEvent(const EcEvent& ec_event) {
    core_delegate()->ec_service()->EmitEcEvent(ec_event);
  }

  void ExpectAllFakeWilcoDtcReceivedEcEvents(
      const std::multiset<GrpcEvent>& expected_ec_events) {
    base::RunLoop run_loop;
    auto barrier_closure = base::BarrierClosure(2 * expected_ec_events.size(),
                                                run_loop.QuitClosure());

    std::multiset<GrpcEvent> fake_wilco_dtc_ec_events;
    std::multiset<GrpcEvent> fake_ui_message_receiver_wilco_dtc_ec_events;
    SetupFakeWilcoDtcEcEventCallback(barrier_closure, fake_wilco_dtc(),
                                     &fake_wilco_dtc_ec_events);
    SetupFakeWilcoDtcEcEventCallback(
        barrier_closure, fake_ui_message_receiver_wilco_dtc(),
        &fake_ui_message_receiver_wilco_dtc_ec_events);

    run_loop.Run();

    EXPECT_EQ(fake_wilco_dtc_ec_events, expected_ec_events);
    EXPECT_EQ(fake_ui_message_receiver_wilco_dtc_ec_events, expected_ec_events);
  }

  std::string GetPayload(const EcEvent& ec_event) const {
    DCHECK_LE(ec_event.size - 1, 6);
    uint16_t payload[6];
    memcpy(&payload, &ec_event.payload, (ec_event.size - 1) * sizeof(uint16_t));
    return ConvertDataInWordsToString(payload, ec_event.size - 1);
  }

  EcEventReason ec_event_reason() const { return std::get<0>(GetParam()); }

  std::optional<MojoEvent> expected_mojo_event() const {
    return std::get<1>(GetParam());
  }

 private:
  void SetupFakeWilcoDtcEcEventCallback(const base::RepeatingClosure& callback,
                                        FakeWilcoDtc* fake_wilco_dtc,
                                        std::multiset<GrpcEvent>* events_out) {
    DCHECK(fake_wilco_dtc);
    DCHECK(events_out);
    fake_wilco_dtc->set_handle_ec_event_request_callback(base::BindRepeating(
        [](const base::RepeatingClosure& callback,
           std::multiset<GrpcEvent>* events_out, int32_t type,
           const std::string& payload) {
          DCHECK(events_out);
          events_out->insert({type, payload});
          callback.Run();
        },
        callback, events_out));
  }
};

// Test that the followings are called by the wilco_dtc support daemon:
// 1. |HandleEcNotification|, exposed by wilco_dtc gRPC, is called on valid
// EC events
// 2. |HandleEvent|, exposed by mojo_client, is called on any EcEvent::Reason
// values except |kSysNotification| and |kNonSysNotification|.
TEST_P(EcServiceBootstrappedCoreTest, SingleEvents) {
  if (expected_mojo_event().has_value()) {
    // Set HandleEvent expectations for the triggered mojo events
    EXPECT_CALL(*wilco_dtc_supportd_client(),
                HandleEvent(expected_mojo_event().value()));
  }
  const EcEvent& ec_event = GetEcEventWithReason(ec_event_reason());
  EmulateEcEvent(ec_event);
  ExpectAllFakeWilcoDtcReceivedEcEvents(
      {{ec_event.type, GetPayload(ec_event)}});
}

// Test that both methods |HandleEcNotification()| and |HandleEvent()| exposed
// by wilco_dtc gRPC and mojo_client, respectively, are called multiple times
// by wilco_dtc support daemon.
TEST_F(EcServiceBootstrappedCoreTest, TriggerMultipleMojoEvents) {
  // Set HandleEvent expectations for the triggered mojo events
  EXPECT_CALL(*wilco_dtc_supportd_client(),
              HandleEvent(MojoEvent::kBatteryAuth));
  EXPECT_CALL(*wilco_dtc_supportd_client(),
              HandleEvent(MojoEvent::kDockDisplay));

  const EcEvent& first_ec_event =
      GetEcEventWithReason(EcEventReason::kBatteryAuth);
  const EcEvent& second_ec_event =
      GetEcEventWithReason(EcEventReason::kDockDisplay);
  EmulateEcEvent(first_ec_event);
  EmulateEcEvent(second_ec_event);

  ExpectAllFakeWilcoDtcReceivedEcEvents(
      {{first_ec_event.type, GetPayload(first_ec_event)},
       {second_ec_event.type, GetPayload(second_ec_event)}});
}

// Test that the method |HandleEcNotification()| exposed by wilco_dtc gRPC is
// not called by the wilco_dtc support daemon when |ec_event.size| exceeds
// allocated data array.
// TODO(mgawad): move size validation logic inside EcService and don't emit
// events when the size is invalid.
TEST_F(EcServiceBootstrappedCoreTest, SendGrpcEventToWilcoDtcInvalidSize) {
  const EcEvent& valid_ec_event =
      GetEcEventWithReason(EcEventReason::kNonSysNotification);
  const EcEvent& invalid_ec_event = kEcEventInvalidPayloadSize;

  EmulateEcEvent(valid_ec_event);
  EmulateEcEvent(invalid_ec_event);

  // Expect only EC event with valid payload size.
  ExpectAllFakeWilcoDtcReceivedEcEvents(
      {{valid_ec_event.type, GetPayload(valid_ec_event)}});
}

INSTANTIATE_TEST_SUITE_P(
    _,
    EcServiceBootstrappedCoreTest,
    testing::Values(
        std::make_tuple(
            EcEventReason::kNonWilcoCharger,
            std::make_optional<MojoEvent>(MojoEvent::kNonWilcoCharger)),
        std::make_tuple(
            EcEventReason::kLowPowerCharger,
            std::make_optional<MojoEvent>(MojoEvent::kLowPowerCharger)),
        std::make_tuple(EcEventReason::kBatteryAuth,
                        std::make_optional<MojoEvent>(MojoEvent::kBatteryAuth)),
        std::make_tuple(EcEventReason::kDockDisplay,
                        std::make_optional<MojoEvent>(MojoEvent::kDockDisplay)),
        std::make_tuple(
            EcEventReason::kDockThunderbolt,
            std::make_optional<MojoEvent>(MojoEvent::kDockThunderbolt)),
        std::make_tuple(
            EcEventReason::kIncompatibleDock,
            std::make_optional<MojoEvent>(MojoEvent::kIncompatibleDock)),
        std::make_tuple(EcEventReason::kDockError,
                        std::make_optional<MojoEvent>(MojoEvent::kDockError)),
        std::make_tuple(EcEventReason::kNonSysNotification, std::nullopt),
        std::make_tuple(EcEventReason::kSysNotification, std::nullopt)));

// Tests for powerd event service.
//
// This is a parametrized test with the following parameters:
// * |power_event| - the power event.
// * |expected_power_event| - the expected power event passed to fake_wilco_dtc
//                            over gRPC.
class PowerdEventServiceBootstrappedCoreTest
    : public BootstrappedCoreTest,
      public testing::WithParamInterface<std::tuple<
          PowerdEventService::Observer::PowerEventType /* power_event */,
          grpc_api::HandlePowerNotificationRequest::
              PowerEvent /* expected_power_event */>> {
 protected:
  PowerdEventService::Observer::PowerEventType power_event() const {
    return std::get<0>(GetParam());
  }
  grpc_api::HandlePowerNotificationRequest::PowerEvent expected_power_event()
      const {
    return std::get<1>(GetParam());
  }

  void SetupFakeWilcoDtcPowerEventCallback(
      const base::RepeatingClosure& callback,
      FakeWilcoDtc* fake_wilco_dtc,
      grpc_api::HandlePowerNotificationRequest::PowerEvent* event_out) {
    DCHECK(fake_wilco_dtc);
    DCHECK(event_out);
    fake_wilco_dtc->set_handle_power_event_request_callback(base::BindRepeating(
        [](const base::RepeatingClosure& callback,
           grpc_api::HandlePowerNotificationRequest::PowerEvent* event_out,
           grpc_api::HandlePowerNotificationRequest::PowerEvent event) {
          DCHECK(event_out);
          *event_out = event;
          callback.Run();
        },
        callback, event_out));
  }
};

// Test that the method |HandlePowerNotification()| exposed by wilco_dtc gRPC is
// called by wilco_dtc support daemon.
TEST_P(PowerdEventServiceBootstrappedCoreTest, PowerEvent) {
  core_delegate()->powerd_event_service()->EmitPowerEvent(power_event());

  base::RunLoop run_loop;
  auto barrier_closure = base::BarrierClosure(2, run_loop.QuitClosure());

  grpc_api::HandlePowerNotificationRequest::PowerEvent
      fake_wilco_dtc_power_event;
  grpc_api::HandlePowerNotificationRequest::PowerEvent
      fake_ui_message_receiver_wilco_dtc_power_event;
  SetupFakeWilcoDtcPowerEventCallback(barrier_closure, fake_wilco_dtc(),
                                      &fake_wilco_dtc_power_event);
  SetupFakeWilcoDtcPowerEventCallback(
      barrier_closure, fake_ui_message_receiver_wilco_dtc(),
      &fake_ui_message_receiver_wilco_dtc_power_event);

  run_loop.Run();

  EXPECT_EQ(fake_wilco_dtc_power_event, expected_power_event());
  EXPECT_EQ(fake_ui_message_receiver_wilco_dtc_power_event,
            expected_power_event());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    PowerdEventServiceBootstrappedCoreTest,
    testing::Values(
        std::make_tuple(PowerdEventService::Observer::PowerEventType::kAcInsert,
                        grpc_api::HandlePowerNotificationRequest::AC_INSERT),
        std::make_tuple(PowerdEventService::Observer::PowerEventType::kAcRemove,
                        grpc_api::HandlePowerNotificationRequest::AC_REMOVE),
        std::make_tuple(
            PowerdEventService::Observer::PowerEventType::kOsSuspend,
            grpc_api::HandlePowerNotificationRequest::OS_SUSPEND),
        std::make_tuple(PowerdEventService::Observer::PowerEventType::kOsResume,
                        grpc_api::HandlePowerNotificationRequest::OS_RESUME)));

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
