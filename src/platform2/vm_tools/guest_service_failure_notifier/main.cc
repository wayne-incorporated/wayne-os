// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <sys/socket.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <base/strings/stringprintf.h>
#include <vm_protos/proto_bindings/vm_crash.grpc.pb.h>
#include <chromeos/constants/vm_tools.h>
#include <grpcpp/grpcpp.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "This tool must be called as ./guest_service_failure_notifier "
                 "service_name"
              << std::endl;
    return 1;
  }

  std::shared_ptr<grpc::Channel> chan =
      grpc::CreateChannel(base::StringPrintf("vsock:%u:%u", VMADDR_CID_HOST,
                                             vm_tools::kCrashListenerPort),
                          grpc::InsecureChannelCredentials());

  vm_tools::cicerone::CrashListener::Stub stub{chan};

  grpc::ClientContext ctx;
  vm_tools::EmptyMessage empty;
  vm_tools::cicerone::FailureReport failure_report;
  failure_report.set_failed_process(argv[1]);
  stub.SendFailureReport(&ctx, failure_report, &empty);

  return 0;
}
