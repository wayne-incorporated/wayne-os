// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/termina_vm.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/mount.h>

#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <base/threading/thread.h>
#include <chromeos/patchpanel/address_manager.h>
#include <chromeos/patchpanel/mac_address_generator.h>
#include <chromeos/patchpanel/subnet.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/message_differencer.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <vm_protos/proto_bindings/vm_guest.grpc.pb.h>

#include "vm_tools/concierge/vsock_cid_pool.h"

using std::string;

namespace pb = google::protobuf;

namespace vm_tools {
namespace concierge {
namespace {

// Converts an IPv4 address in network byte order into a string.
bool IPv4AddressToString(uint32_t addr, string* address) {
  CHECK(address);

  char buf[INET_ADDRSTRLEN];
  struct in_addr in = {
      .s_addr = addr,
  };
  if (inet_ntop(AF_INET, &in, buf, sizeof(buf)) == nullptr) {
    PLOG(ERROR) << "Failed to convert " << addr << " into a string";
    return false;
  }

  *address = buf;
  return true;
}

// Name of the unix domain socket for the grpc server.
constexpr char kServerSocket[] = "server";

// Sample Termina kernel version.
constexpr char kKernelVersion[] = "some kernel version";

// Test fixture for actually testing the TerminaVm functionality.
class TerminaVmTest : public ::testing::Test {
 public:
  TerminaVmTest() = default;
  TerminaVmTest(const TerminaVmTest&) = delete;
  TerminaVmTest& operator=(const TerminaVmTest&) = delete;

  ~TerminaVmTest() override = default;

  // Called by FakeMaitredService to indicate a test failure.
  void TestFailed(string reason);

  // Called by FakeMaitredService for checking the ConfigureNetwork RPC.
  const string& address() const { return address_; }
  const string& netmask() const { return netmask_; }
  const string& gateway() const { return gateway_; }

  // Called by FakeMaitredService the first time it receives a LaunchProcess
  // RPC.
  std::deque<vm_tools::LaunchProcessRequest> launch_requests() {
    return std::move(launch_requests_);
  }

  // Called by FakeMaitredService the first time it receives a Mount RPC.
  std::deque<vm_tools::MountRequest> mount_requests() {
    return std::move(mount_requests_);
  }

 protected:
  // ::testing::Test overrides.
  void SetUp() override;
  void TearDown() override;

 private:
  // Posted back to the main thread by the grpc thread after starting the
  // server.
  void ServerStartCallback(base::OnceClosure quit,
                           std::shared_ptr<grpc::Server> server);

  // The message loop for the current thread.  Declared here because it must be
  // the last thing to be cleaned up.
  base::test::TaskEnvironment task_environment_;
  base::FileDescriptorWatcher watcher_{
      task_environment_.GetMainThreadTaskRunner()};

 protected:
  // Actual virtual machine being tested.
  std::unique_ptr<TerminaVm> vm_;

  // Expected LaunchProcessRequests. Tests should fill this with all the
  // LaunchProcessRequests that it expects the TerminaVm to receive. These
  // will be moved into the FakeMaitredService the first time it receives a
  // LaunchProcess RPC.
  std::deque<vm_tools::LaunchProcessRequest> launch_requests_;

  // Expected MountRequests.  Tests should fill this with all the MountRequests
  // that they expect a TerminaVm to receive.  These will be moved to the
  // FakeMaitredService the firest time it receives a Mount RPC.
  std::deque<vm_tools::MountRequest> mount_requests_;

  // Set when a failure occurs.
  bool failed_{false};
  string failure_reason_;

 private:
  // Temporary directory where we will store our socket.
  base::ScopedTempDir temp_dir_;

  // Resource allocators for the VM.
  std::unique_ptr<patchpanel::AddressManager> network_address_manager_;
  patchpanel::MacAddressGenerator mac_address_generator_;
  VsockCidPool vsock_cid_pool_;

  // Addresses assigned to the VM.
  string address_;
  string netmask_;
  string gateway_;

  // The thread on which the server will run.
  base::Thread server_thread_{"gRPC maitre'd thread"};

  // grpc::Server that will handle the requests.
  std::shared_ptr<grpc::Server> server_;

  base::WeakPtrFactory<TerminaVmTest> weak_factory_{this};
};

// Test server that verifies the RPCs it receives with the expected RPCs.
class FakeMaitredService final : public vm_tools::Maitred::Service {
 public:
  explicit FakeMaitredService(TerminaVmTest* vm_test);
  FakeMaitredService(const FakeMaitredService&) = delete;
  FakeMaitredService& operator=(const FakeMaitredService&) = delete;

  ~FakeMaitredService() override = default;

  // Maitred::Service overrides.
  grpc::Status LaunchProcess(
      grpc::ServerContext* ctx,
      const vm_tools::LaunchProcessRequest* request,
      vm_tools::LaunchProcessResponse* response) override;
  grpc::Status ConfigureNetwork(grpc::ServerContext* ctx,
                                const vm_tools::NetworkConfigRequest* request,
                                vm_tools::EmptyMessage* response) override;
  grpc::Status Mount(grpc::ServerContext* ctx,
                     const vm_tools::MountRequest* request,
                     vm_tools::MountResponse* response) override;
  grpc::Status Shutdown(grpc::ServerContext* ctx,
                        const vm_tools::EmptyMessage* request,
                        vm_tools::EmptyMessage* response) override;
  grpc::Status SetTime(grpc::ServerContext* ctx,
                       const vm_tools::SetTimeRequest* request,
                       vm_tools::EmptyMessage* response) override;
  grpc::Status SetResolvConfig(grpc::ServerContext* ctx,
                               const vm_tools::SetResolvConfigRequest* request,
                               vm_tools::EmptyMessage* response) override;

 private:
  // Populated the first time this class receives a LaunchProcess RPC.
  std::deque<vm_tools::LaunchProcessRequest> launch_requests_;

  // Set to true when launch_requests_ has been populated.
  bool launch_requests_initialized_;

  // Populated the first time this class receives a MountProcess RPC.
  std::deque<vm_tools::MountRequest> mount_requests_;

  // Set to true when mount_requests_ has been populated.
  bool mount_requests_initialized_;

  // Non-owning pointer to the test fixture.  Valid for the lifetime of this
  // object because this lives on the grpc thread, which is a member of the test
  // fixture.  The cross-thread access is safe because all the TerminaVm
  // RPCs are synchronous, which means the main thread will be blocked while the
  // grpc thread is processing the RPC.
  TerminaVmTest* vm_test_;
};

FakeMaitredService::FakeMaitredService(TerminaVmTest* vm_test)
    : launch_requests_initialized_(false),
      mount_requests_initialized_(false),
      vm_test_(vm_test) {}

grpc::Status FakeMaitredService::LaunchProcess(
    grpc::ServerContext* ctx,
    const vm_tools::LaunchProcessRequest* request,
    vm_tools::LaunchProcessResponse* response) {
  if (!launch_requests_initialized_) {
    launch_requests_ = vm_test_->launch_requests();
    launch_requests_initialized_ = true;
  }

  if (launch_requests_.empty()) {
    vm_test_->TestFailed("Received LaunchProcessRequest with empty deque");
    return grpc::Status::OK;
  }

  vm_tools::LaunchProcessRequest expected = std::move(launch_requests_.front());
  launch_requests_.pop_front();

  string difference;
  pb::util::MessageDifferencer differencer;
  differencer.ReportDifferencesToString(&difference);
  if (!differencer.Compare(expected, *request)) {
    vm_test_->TestFailed("Mismatched LaunchProcessRequests: " + difference);
  }
  return grpc::Status::OK;
}

grpc::Status FakeMaitredService::ConfigureNetwork(
    grpc::ServerContext* ctx,
    const vm_tools::NetworkConfigRequest* request,
    vm_tools::EmptyMessage* response) {
  string address;
  if (!IPv4AddressToString(request->ipv4_config().address(), &address)) {
    vm_test_->TestFailed(
        base::StringPrintf("Failed to parse address %u into a string",
                           request->ipv4_config().address()));
    return grpc::Status::OK;
  }
  if (address != vm_test_->address()) {
    vm_test_->TestFailed(
        base::StringPrintf("Mismatched addresses: expected %s got %s",
                           vm_test_->address().c_str(), address.c_str()));
    return grpc::Status::OK;
  }

  string netmask;
  if (!IPv4AddressToString(request->ipv4_config().netmask(), &netmask)) {
    vm_test_->TestFailed(
        base::StringPrintf("Failed to parse netmask %u into a string",
                           request->ipv4_config().netmask()));
    return grpc::Status::OK;
  }
  if (netmask != vm_test_->netmask()) {
    vm_test_->TestFailed(
        base::StringPrintf("Mismatched netmasks: expected %s got %s",
                           vm_test_->netmask().c_str(), netmask.c_str()));
    return grpc::Status::OK;
  }

  string gateway;
  if (!IPv4AddressToString(request->ipv4_config().gateway(), &gateway)) {
    vm_test_->TestFailed(
        base::StringPrintf("Failed to parse gateway %u into a string",
                           request->ipv4_config().gateway()));
    return grpc::Status::OK;
  }
  if (gateway != vm_test_->gateway()) {
    vm_test_->TestFailed(
        base::StringPrintf("Mismatched gateways: expected %s got %s",
                           vm_test_->gateway().c_str(), gateway.c_str()));
    return grpc::Status::OK;
  }

  return grpc::Status::OK;
}

grpc::Status FakeMaitredService::Mount(grpc::ServerContext* ctx,
                                       const vm_tools::MountRequest* request,
                                       vm_tools::MountResponse* response) {
  if (!mount_requests_initialized_) {
    mount_requests_ = vm_test_->mount_requests();
    mount_requests_initialized_ = true;
  }

  if (mount_requests_.empty()) {
    vm_test_->TestFailed("Received MountRequest with empty deque");
    return grpc::Status::OK;
  }

  vm_tools::MountRequest expected = std::move(mount_requests_.front());
  mount_requests_.pop_front();

  string difference;
  pb::util::MessageDifferencer differencer;
  differencer.ReportDifferencesToString(&difference);
  if (!differencer.Compare(expected, *request)) {
    vm_test_->TestFailed("Mismatched MountRequests: " + difference);
  }
  return grpc::Status::OK;
}

grpc::Status FakeMaitredService::Shutdown(grpc::ServerContext* ctx,
                                          const vm_tools::EmptyMessage* request,
                                          vm_tools::EmptyMessage* response) {
  return grpc::Status::OK;
}

grpc::Status FakeMaitredService::SetTime(
    grpc::ServerContext* ctx,
    const vm_tools::SetTimeRequest* request,
    vm_tools::EmptyMessage* response) {
  return grpc::Status::OK;
}

grpc::Status FakeMaitredService::SetResolvConfig(
    grpc::ServerContext* ctx,
    const vm_tools::SetResolvConfigRequest* request,
    vm_tools::EmptyMessage* response) {
  return grpc::Status::OK;
}

// Runs on the grpc thread and starts the grpc server.
void StartFakeMaitredService(
    TerminaVmTest* vm_test,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    base::FilePath listen_path,
    base::OnceCallback<void(std::shared_ptr<grpc::Server>)> server_cb) {
  FakeMaitredService maitred(vm_test);

  grpc::ServerBuilder builder;
  builder.AddListeningPort("unix:" + listen_path.value(),
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&maitred);

  std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());
  main_task_runner->PostTask(FROM_HERE,
                             base::BindOnce(std::move(server_cb), server));

  if (server) {
    // This will not race with shutdown because the grpc server code includes a
    // check to see if the server has already been shut down (or is shutting
    // down) when Wait is called.
    server->Wait();
  }
}

void TerminaVmTest::SetUp() {
  // Create the temporary directory.
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

  // Start the FakeMaitredService on a different thread.
  base::RunLoop run_loop;

  ASSERT_TRUE(server_thread_.Start());
  server_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &StartFakeMaitredService, this,
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          temp_dir_.GetPath().Append(kServerSocket),
          base::BindOnce(&TerminaVmTest::ServerStartCallback,
                         weak_factory_.GetWeakPtr(), run_loop.QuitClosure())));

  run_loop.Run();

  ASSERT_TRUE(server_);

  // Create the stub to the FakeMaitredService.
  std::unique_ptr<vm_tools::Maitred::Stub> stub =
      vm_tools::Maitred::NewStub(grpc::CreateChannel(
          "unix:" + temp_dir_.GetPath().Append(kServerSocket).value(),
          grpc::InsecureChannelCredentials()));
  ASSERT_TRUE(stub);

  // Allocate resources for the VM.
  network_address_manager_.reset(new patchpanel::AddressManager());
  uint32_t vsock_cid = vsock_cid_pool_.Allocate();
  std::unique_ptr<patchpanel::Subnet> subnet =
      network_address_manager_->AllocateIPv4Subnet(
          patchpanel::AddressManager::GuestType::kTerminaVM);

  ASSERT_TRUE(subnet);

  ASSERT_TRUE(IPv4AddressToString(
      subnet->CIDRAtOffset(2)->address().ToInAddr().s_addr, &address_));
  ASSERT_TRUE(IPv4AddressToString(
      subnet->base_cidr().ToNetmask().ToInAddr().s_addr, &netmask_));
  ASSERT_TRUE(IPv4AddressToString(
      subnet->CIDRAtOffset(1)->address().ToInAddr().s_addr, &gateway_));

  std::string stateful_device = "/dev/vdb";
  uint64_t stateful_size = (uint64_t)20 * 1024 * 1024 * 1024;

  // Create the TerminaVm.
  VmBuilder vm_builder;
  vm_builder.SetRootfs({.device = "/dev/vda", .path = base::FilePath("dummy")});
  vm_ = TerminaVm::CreateForTesting(
      std::move(subnet), vsock_cid, temp_dir_.GetPath(), base::FilePath(),
      std::move(stateful_device), stateful_size, kKernelVersion,
      std::move(stub), std::move(vm_builder));
  ASSERT_TRUE(vm_);
}

void TerminaVmTest::TearDown() {
  // Do the opposite of SetUp to make sure things get cleaned up in the right
  // order.
  vm_.reset();
  server_->Shutdown();
  server_.reset();
  server_thread_.Stop();
}

void TerminaVmTest::ServerStartCallback(base::OnceClosure quit,
                                        std::shared_ptr<grpc::Server> server) {
  server_.swap(server);
  std::move(quit).Run();
}

void TerminaVmTest::TestFailed(string reason) {
  failed_ = true;
  failure_reason_ = std::move(reason);
}

}  // namespace

TEST_F(TerminaVmTest, ConfigureNetwork) {
  ASSERT_TRUE(vm_->ConfigureNetwork({"8.8.8.8"}, {}));

  EXPECT_FALSE(failed_) << "Failure reason: " << failure_reason_;
}

TEST_F(TerminaVmTest, SetTime) {
  string reason;
  bool success = vm_->SetTime(&reason);
  EXPECT_TRUE(success) << reason;

  EXPECT_FALSE(failed_) << "Failure reason: " << failure_reason_;
}

TEST_F(TerminaVmTest, Mount) {
  struct {
    const char* source;
    const char* target;
    const char* fstype;
    uint64_t flags;
    const char* opts;
  } mounts[] = {
      {
          .source = "100.115.92.25:/my/home/directory",
          .target = "/mnt/shared",
          .fstype = "nfs",
          .flags = 0,
          .opts = "nolock,vers=3,addr=100.115.92.25",
      },
      {
          .source = "/dev/vdb",
          .target = "/mnt/container_rootfs",
          .fstype = "ext4",
          .flags = MS_RDONLY,
          .opts = "",
      },
  };

  // Build the expected protobufs.
  for (const auto& mt : mounts) {
    vm_tools::MountRequest request;

    request.set_source(mt.source);
    request.set_target(mt.target);
    request.set_fstype(mt.fstype);
    request.set_mountflags(mt.flags);
    request.set_options(mt.opts);

    mount_requests_.emplace_back(std::move(request));
  }

  // Make the requests.
  for (const auto& mt : mounts) {
    ASSERT_TRUE(vm_->Mount(mt.source, mt.target, mt.fstype, mt.flags, mt.opts));

    EXPECT_FALSE(failed_) << "Failure reason: " << failure_reason_;
  }
}

TEST_F(TerminaVmTest, GetVmEnterpriseReportingInfo) {
  GetVmEnterpriseReportingInfoResponse response;
  bool result = vm_->GetVmEnterpriseReportingInfo(&response);
  EXPECT_TRUE(result);
  EXPECT_EQ(kKernelVersion, response.vm_kernel_version());
}

}  // namespace concierge
}  // namespace vm_tools
