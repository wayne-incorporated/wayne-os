// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "google/protobuf/message_lite.h"
#include "missive/proto/record_constants.pb.h"
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/device_user.h"
#include "secagentd/message_sender.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd {

namespace pb = cros_xdr::reporting;

namespace {

// Fills a Namespaces proto with contents from bpf namespace_info.
void FillNamespaces(const bpf::cros_namespace_info& ns,
                    pb::Namespaces* ns_proto) {
  ns_proto->set_cgroup_ns(ns.cgroup_ns);
  ns_proto->set_pid_ns(ns.pid_ns);
  ns_proto->set_user_ns(ns.user_ns);
  ns_proto->set_uts_ns(ns.uts_ns);
  ns_proto->set_mnt_ns(ns.mnt_ns);
  ns_proto->set_net_ns(ns.net_ns);
  ns_proto->set_ipc_ns(ns.ipc_ns);
}

std::string GetBatchedEventKey(
    const pb::ProcessEventAtomicVariant& process_event) {
  switch (process_event.variant_type_case()) {
    case cros_xdr::reporting::ProcessEventAtomicVariant::kProcessExec:
      return process_event.process_exec().spawn_process().process_uuid();
    case cros_xdr::reporting::ProcessEventAtomicVariant::kProcessTerminate:
      return process_event.process_terminate().process().process_uuid();
    case cros_xdr::reporting::ProcessEventAtomicVariant::VARIANT_TYPE_NOT_SET:
      return "";
  }
}

void SetTerminateTimestamp(pb::ProcessEventAtomicVariant* exec) {
  if (exec->has_process_exec()) {
    exec->mutable_process_exec()->set_terminate_timestamp_us(
        base::Time::Now().ToJavaTime() *
        base::Time::kMicrosecondsPerMillisecond);
  }
}

}  // namespace

ProcessPlugin::ProcessPlugin(
    scoped_refptr<BpfSkeletonFactoryInterface> bpf_skeleton_factory,
    scoped_refptr<MessageSenderInterface> message_sender,
    scoped_refptr<ProcessCacheInterface> process_cache,
    scoped_refptr<PoliciesFeaturesBrokerInterface> policies_features_broker,
    scoped_refptr<DeviceUserInterface> device_user,
    uint32_t batch_interval_s)
    : weak_ptr_factory_(this),
      process_cache_(process_cache),
      policies_features_broker_(policies_features_broker),
      device_user_(device_user),
      batch_sender_(
          std::make_unique<BatchSender<std::string,
                                       pb::XdrProcessEvent,
                                       pb::ProcessEventAtomicVariant>>(
              base::BindRepeating(&GetBatchedEventKey),
              message_sender,
              reporting::Destination::CROS_SECURITY_PROCESS,
              batch_interval_s)) {
  CHECK(message_sender != nullptr);
  CHECK(process_cache != nullptr);
  CHECK(bpf_skeleton_factory);
  factory_ = std::move(bpf_skeleton_factory);
}

std::string ProcessPlugin::GetName() const {
  return "Process";
}

void ProcessPlugin::HandleRingBufferEvent(const bpf::cros_event& bpf_event) {
  auto atomic_event = std::make_unique<pb::ProcessEventAtomicVariant>();
  if (bpf_event.type != bpf::kProcessEvent) {
    LOG(ERROR) << "ProcessBPF: unknown BPF event type.";
    return;
  }
  const bpf::cros_process_event& pe = bpf_event.data.process_event;
  if (pe.type == bpf::kProcessStartEvent) {
    const bpf::cros_process_start& process_start = pe.data.process_start;
    // Record the newly spawned process into our cache.
    process_cache_->PutFromBpfExec(process_start);
    auto exec_event = MakeExecEvent(process_start);
    const pb::Process* parent_process =
        exec_event->has_process() ? exec_event->mutable_process() : nullptr;
    const pb::Process* process = exec_event->has_spawn_process()
                                     ? exec_event->mutable_spawn_process()
                                     : nullptr;
    if (process_cache_->IsEventFiltered(parent_process, process)) {
      return;
    }
    atomic_event->set_allocated_process_exec(exec_event.release());
  } else if (pe.type == bpf::kProcessExitEvent) {
    const bpf::cros_process_exit& process_exit = pe.data.process_exit;
    auto terminate_event = MakeTerminateEvent(process_exit);
    if (process_exit.is_leaf) {
      process_cache_->EraseProcess(process_exit.task_info.pid,
                                   process_exit.task_info.start_time);
    }
    const pb::Process* parent_process =
        terminate_event->has_parent_process()
            ? terminate_event->mutable_parent_process()
            : nullptr;
    const pb::Process* process = terminate_event->has_process()
                                     ? terminate_event->mutable_process()
                                     : nullptr;
    if (process_cache_->IsEventFiltered(parent_process, process)) {
      return;
    }
    atomic_event->set_allocated_process_terminate(terminate_event.release());
  } else {
    LOG(ERROR) << "ProcessBPF: unknown BPF process event type.";
    return;
  }

  atomic_event->mutable_common()->set_device_user(
      device_user_->GetDeviceUser());
  EnqueueBatchedEvent(std::move(atomic_event));
}

void ProcessPlugin::HandleBpfRingBufferReadReady() const {
  skeleton_wrapper_->ConsumeEvent();
}

absl::Status ProcessPlugin::Activate() {
  // If already called do nothing and report Ok.
  if (skeleton_wrapper_) {
    return absl::OkStatus();
  }

  struct BpfCallbacks callbacks;
  callbacks.ring_buffer_event_callback = base::BindRepeating(
      &ProcessPlugin::HandleRingBufferEvent, weak_ptr_factory_.GetWeakPtr());
  callbacks.ring_buffer_read_ready_callback =
      base::BindRepeating(&ProcessPlugin::HandleBpfRingBufferReadReady,
                          weak_ptr_factory_.GetWeakPtr());
  skeleton_wrapper_ =
      factory_->Create(Types::BpfSkeleton::kProcess, std::move(callbacks), 0);
  if (skeleton_wrapper_ == nullptr) {
    return absl::InternalError("Process BPF program loading error.");
  }
  batch_sender_->Start();
  return absl::OkStatus();
}

absl::Status ProcessPlugin::Deactivate() {
  return absl::UnimplementedError(
      "Deactivate not implemented for ProcessPlugin.");
}

void ProcessPlugin::EnqueueBatchedEvent(
    std::unique_ptr<pb::ProcessEventAtomicVariant> atomic_event) {
  if (atomic_event->has_process_terminate() &&
      policies_features_broker_->GetFeature(
          PoliciesFeaturesBroker::Feature::
              kCrOSLateBootSecagentdCoalesceTerminates)) {
    if (batch_sender_->Visit(pb::ProcessEventAtomicVariant::kProcessExec,
                             GetBatchedEventKey(*atomic_event),
                             base::BindOnce(&SetTerminateTimestamp))) {
      // Successfully visited and presumably also coalesced.
      return;
    }
  }
  batch_sender_->Enqueue(std::move(atomic_event));
}

bool ProcessPlugin::IsActive() const {
  return skeleton_wrapper_ != nullptr;
}

std::unique_ptr<pb::ProcessExecEvent> ProcessPlugin::MakeExecEvent(
    const bpf::cros_process_start& process_start) {
  auto process_exec_event = std::make_unique<pb::ProcessExecEvent>();
  FillNamespaces(process_start.spawn_namespace,
                 process_exec_event->mutable_spawn_namespaces());
  // Fetch information on process that was just spawned, the parent process
  // that spawned that process, and its parent process. I.e a total of
  // three.
  auto hierarchy = process_cache_->GetProcessHierarchy(
      process_start.task_info.pid, process_start.task_info.start_time, 3);
  if (hierarchy.empty()) {
    LOG(ERROR) << "PID:" << process_start.task_info.pid
               << " not found in the process cache.";
  }

  if (hierarchy.size() > 0) {
    process_exec_event->set_allocated_spawn_process(hierarchy[0].release());
  }

  if (hierarchy.size() > 1) {
    process_exec_event->set_allocated_process(hierarchy[1].release());
  }

  if (hierarchy.size() > 2) {
    process_exec_event->set_allocated_parent_process(hierarchy[2].release());
  }

  // Exec event metrics.
  metrics::ProcessEvent exec_event_metric = metrics::ProcessEvent::kFullEvent;
  if (hierarchy.empty()) {
    exec_event_metric = metrics::ProcessEvent::kSpawnPidNotInCache;
  } else if (hierarchy.size() == 1) {
    exec_event_metric = metrics::ProcessEvent::kProcessPidNotInCache;
  } else if (hierarchy.size() == 2 && process_exec_event->has_process() &&
             process_exec_event->process().canonical_pid() > 1) {
    exec_event_metric = metrics::ProcessEvent::kParentPidNotInCache;
  }
  MetricsSender::GetInstance().IncrementBatchedMetric(metrics::kExecEvent,
                                                      exec_event_metric);

  return process_exec_event;
}

std::unique_ptr<pb::ProcessTerminateEvent> ProcessPlugin::MakeTerminateEvent(
    const bpf::cros_process_exit& process_exit) {
  auto process_terminate_event = std::make_unique<pb::ProcessTerminateEvent>();
  // Try to fetch from the process cache if possible. The cache has more
  // complete information.
  auto hierarchy = process_cache_->GetProcessHierarchy(
      process_exit.task_info.pid, process_exit.task_info.start_time, 2);

  // If that fails, fill in the task info that we got from BPF.
  if (hierarchy.empty()) {
    ProcessCache::PartiallyFillProcessFromBpfTaskInfo(
        process_exit.task_info, process_terminate_event->mutable_process());
    // Maybe the parent is still alive and in procfs.
    auto parent = process_cache_->GetProcessHierarchy(
        process_exit.task_info.ppid, process_exit.task_info.parent_start_time,
        1);
    if (parent.size() != 0) {
      process_terminate_event->set_allocated_parent_process(
          parent[0].release());
    }
  }

  if (hierarchy.size() > 0) {
    process_terminate_event->set_allocated_process(hierarchy[0].release());
  }

  if (hierarchy.size() > 1) {
    process_terminate_event->set_allocated_parent_process(
        hierarchy[1].release());
  }

  // Terminate event metrics.
  metrics::ProcessEvent terminate_event_metric =
      metrics::ProcessEvent::kFullEvent;
  if (hierarchy.empty()) {
    if (process_terminate_event->has_process()) {
      terminate_event_metric = metrics::ProcessEvent::kParentStillAlive;
    } else {
      terminate_event_metric = metrics::ProcessEvent::kProcessPidNotInCache;
    }
  } else if (hierarchy.size() == 1 && process_terminate_event->has_process() &&
             process_terminate_event->process().canonical_pid() > 1) {
    terminate_event_metric = metrics::ProcessEvent::kParentPidNotInCache;
  }
  MetricsSender::GetInstance().IncrementBatchedMetric(metrics::kTerminateEvent,
                                                      terminate_event_metric);

  return process_terminate_event;
}

}  // namespace secagentd
