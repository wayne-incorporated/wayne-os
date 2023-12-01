// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_CRASH_LISTENER_IMPL_H_
#define VM_TOOLS_CICERONE_CRASH_LISTENER_IMPL_H_

#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/sequenced_task_runner.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <vm_protos/proto_bindings/vm_crash.grpc.pb.h>

#include "metrics/metrics_library.h"

namespace vm_tools {
namespace cicerone {

class Service;
class VirtualMachine;

class CrashListenerImpl : public CrashListener::Service {
 public:
  explicit CrashListenerImpl(
      base::WeakPtr<vm_tools::cicerone::Service> service);
  CrashListenerImpl(const CrashListenerImpl&) = delete;
  CrashListenerImpl& operator=(const CrashListenerImpl&) = delete;
  ~CrashListenerImpl() override = default;

  grpc::Status CheckMetricsConsent(grpc::ServerContext* ctx,
                                   const EmptyMessage* request,
                                   MetricsConsentResponse* response) override;

  grpc::Status SendCrashReport(grpc::ServerContext* ctx,
                               const CrashReport* crash_report,
                               EmptyMessage* response) override;

  grpc::Status SendFailureReport(grpc::ServerContext* ctx,
                                 const FailureReport* failure_report,
                                 EmptyMessage* response) override;

 private:
  FRIEND_TEST(CrashListenerImplTest, CorrectMetadataChanged);
  std::optional<pid_t> GetPidFromPeerAddress(grpc::ServerContext* ctx);
  VirtualMachine* GetVirtualMachineForContext(grpc::ServerContext* ctx);

  void GetVirtualMachineForCidOrToken(const uint32_t cid,
                                      VirtualMachine** vm_out,
                                      std::string* owner_id_out,
                                      std::string* name_out,
                                      bool* ret_value,
                                      base::WaitableEvent* event);

  bool ShouldRecordFailures(grpc::ServerContext* ctx);

  void GetVmStoppingOnDBusThread(const uint32_t cid,
                                 bool* is_stopping_or_stopped,
                                 base::WaitableEvent* event);

  // Returns a modified copy of crash_report with channel and milestone
  CrashReport ModifyCrashReport(const CrashReport* crash_report);

  virtual std::string GetLsbReleaseValue(std::string key);

  MetricsLibrary metrics_{};

  base::WeakPtr<vm_tools::cicerone::Service> service_;  // not owned
  // Task runner for the DBus thread; requests to perform DBus operations
  // on |service_| generally need to be posted to this thread.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_CRASH_LISTENER_IMPL_H_
