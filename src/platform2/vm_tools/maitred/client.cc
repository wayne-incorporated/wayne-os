// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <limits>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/flag_helper.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/message.h>
#include <google/protobuf/text_format.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_guest.grpc.pb.h>

using std::string;

namespace pb = google::protobuf;

namespace {

// Timeout in seconds for each gRPC call.
constexpr int kDefaultTimeoutSeconds = 10;

bool ParseFileToProto(base::FilePath path, pb::Message* msg) {
  if (!base::PathExists(path)) {
    LOG(ERROR) << path.value() << " does not exist";
    return false;
  }

  base::ScopedFD fd(open(path.value().c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Unable to open file at " << path.value();
    return false;
  }

  pb::io::FileInputStream stream(fd.get());
  return pb::TextFormat::Parse(&stream, msg);
}

bool ConfigureNetwork(vm_tools::Maitred::Stub* stub, base::FilePath path) {
  LOG(INFO) << "Attempting to configure VM network";

  vm_tools::NetworkConfigRequest request;
  if (!ParseFileToProto(path, &request)) {
    LOG(ERROR) << "Unable to parse proto file";
    return false;
  }

  // Make the RPC.
  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::EmptyMessage empty;

  grpc::Status status = stub->ConfigureNetwork(&ctx, request, &empty);

  if (status.ok()) {
    LOG(INFO) << "Successfully configured network";
  } else {
    LOG(ERROR) << "Failed to configure network: " << status.error_message();
  }

  return true;
}

void Shutdown(vm_tools::Maitred::Stub* stub) {
  LOG(INFO) << "Shutting down VM";

  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::EmptyMessage empty;

  grpc::Status status = stub->Shutdown(&ctx, empty, &empty);

  if (status.ok()) {
    LOG(INFO) << "Successfully shut down VM";
  } else {
    LOG(ERROR) << "Failed to shut down VM: " << status.error_message();
  }
}

bool LaunchProcess(vm_tools::Maitred::Stub* stub, base::FilePath path) {
  LOG(INFO) << "Attempting to launch process";

  vm_tools::LaunchProcessRequest request;
  if (!ParseFileToProto(path, &request)) {
    LOG(ERROR) << "Unable to parse proto file";
    return false;
  }

  // Make the RPC.
  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::LaunchProcessResponse response;

  grpc::Status status = stub->LaunchProcess(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to launch process " << request.argv()[0] << ": "
               << status.error_message();
    return true;
  }

  switch (response.status()) {
    case vm_tools::UNKNOWN:
      LOG(WARNING) << "RPC completed with unknown process status";
      break;
    case vm_tools::EXITED:
      LOG(INFO) << "Process exited with status " << response.code();
      break;
    case vm_tools::SIGNALED:
      LOG(INFO) << "Process killed by signal " << response.code();
      break;
    case vm_tools::FAILED:
      LOG(ERROR) << "Failed to launch process.  Please inspect maitre'd logs "
                 << "for the failure details.";
      break;
    case vm_tools::LAUNCHED:
      LOG(INFO) << "Successfully launched process " << request.argv()[0];
      break;
    default:
      LOG(WARNING) << "Received unknown process status from server: "
                   << response.status();
      break;
  }

  return true;
}

bool Mount(vm_tools::Maitred::Stub* stub, base::FilePath path) {
  LOG(INFO) << "Attempting to mount filesystem";

  vm_tools::MountRequest request;
  if (!ParseFileToProto(path, &request)) {
    LOG(ERROR) << "Unable to parse proto file";
    return false;
  }

  // Make the RPC.
  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::MountResponse response;

  grpc::Status status = stub->Mount(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send mount RPC " << request.source() << " -> "
               << request.target() << ": " << status.error_message();
    return true;
  }

  if (response.error() != 0) {
    LOG(ERROR) << "Failed to mount " << request.source() << " -> "
               << request.target() << ": " << strerror(response.error());
    return false;
  }

  LOG(INFO) << "Mount successful " << request.source() << " -> "
            << request.target();
  return true;
}

bool Mount9P(vm_tools::Maitred::Stub* stub, base::FilePath path) {
  LOG(INFO) << "Attempting to mount 9p filesystem";

  vm_tools::Mount9PRequest request;
  if (!ParseFileToProto(path, &request)) {
    LOG(ERROR) << "Unable to parse proto file";
    return false;
  }

  // Make the RPC.
  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::MountResponse response;

  grpc::Status status = stub->Mount9P(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send Mount9P RPC: " << status.error_message();
    return true;
  }

  if (response.error() != 0) {
    LOG(ERROR) << "Failed to mount VMADDR_CID_HOST:" << request.port() << " -> "
               << request.target() << ": " << strerror(response.error());
    return false;
  }

  LOG(INFO) << "Mount successful VMADDR_CID_HOST:" << request.port() << " -> "
            << request.target();
  return true;
}

bool SetTime(vm_tools::Maitred::Stub* stub, uint64_t time) {
  LOG(INFO) << "Attempting to set time of day";

  vm_tools::SetTimeRequest request;
  google::protobuf::Timestamp* timestamp = request.mutable_time();
  timestamp->set_seconds(time);
  timestamp->set_nanos(0);

  // Make the RPC.
  grpc::ClientContext ctx;
  ctx.set_deadline(gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_seconds(kDefaultTimeoutSeconds, GPR_TIMESPAN)));
  vm_tools::EmptyMessage response;

  grpc::Status status = stub->SetTime(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send SetTime RPC: " << status.error_message();
    return false;
  }

  LOG(INFO) << "Successfully set time.";
  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  base::AtExitManager at_exit;

  // Force gRPC to use the native resolver instead of ares.
  // TODO(crbug.com/1044665): Remove once gRPC doesn't use ares resolver for
  // vsock.
  setenv("GRPC_DNS_RESOLVER", "native", 1);

  DEFINE_uint64(cid, 0, "Cid of VM");
  DEFINE_uint64(port, 0, "Port number where maitred is listening");
  DEFINE_string(configure_network, "",
                "Path to NetworkConfigRequest text proto file");
  DEFINE_string(launch_process, "",
                "Path to LaunchProcessRequest text proto file");
  DEFINE_string(mount, "", "Path to MountRequest text proto file");
  DEFINE_string(mount_9p, "", "Path to Mount9PRequest text proto file");
  DEFINE_bool(shutdown, false, "Shutdown the VM");
  DEFINE_uint64(set_time_sec, 0,
                "Set VM time to specified seconds since epoch.");
  brillo::FlagHelper::Init(argc, argv, "maitred client tool");
  if (FLAGS_cid == 0) {
    LOG(ERROR) << "--cid flag is required";
    return EXIT_FAILURE;
  }
  if (FLAGS_port == 0) {
    LOG(ERROR) << "--port flag is required";
    return EXIT_FAILURE;
  }

  unsigned int cid = FLAGS_cid;
  if (static_cast<uint64_t>(cid) != FLAGS_cid) {
    LOG(ERROR) << "Cid value (" << FLAGS_cid << ") is too large.  Largest "
               << "valid value is " << std::numeric_limits<unsigned int>::max();
    return EXIT_FAILURE;
  }

  unsigned int port = FLAGS_port;
  if (static_cast<uint64_t>(port) != FLAGS_port) {
    LOG(ERROR) << "Port value (" << FLAGS_port << ") is too large.  Largest "
               << "valid value is " << std::numeric_limits<unsigned int>::max();
    return EXIT_FAILURE;
  }

  vm_tools::Maitred::Stub stub(
      grpc::CreateChannel(base::StringPrintf("vsock:%u:%u", cid, port),
                          grpc::InsecureChannelCredentials()));

  bool success = true;
  if (!FLAGS_configure_network.empty()) {
    success = ConfigureNetwork(&stub, base::FilePath(FLAGS_configure_network));
  } else if (!FLAGS_launch_process.empty()) {
    success = LaunchProcess(&stub, base::FilePath(FLAGS_launch_process));
  } else if (!FLAGS_mount.empty()) {
    success = Mount(&stub, base::FilePath(FLAGS_mount));
  } else if (!FLAGS_mount_9p.empty()) {
    success = Mount9P(&stub, base::FilePath(FLAGS_mount_9p));
  } else if (FLAGS_shutdown) {
    Shutdown(&stub);
  } else if (FLAGS_set_time_sec != 0) {
    success = SetTime(&stub, FLAGS_set_time_sec);
  } else {
    LOG(WARNING) << "No commands specified";
  }

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
