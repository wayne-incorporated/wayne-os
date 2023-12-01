// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_BPF_SKELETON_WRAPPERS_H_
#define SECAGENTD_BPF_SKELETON_WRAPPERS_H_

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "base/files/file_descriptor_watcher_posix.h"
#include "base/functional/callback.h"
#include "base/functional/callback_forward.h"
#include "base/strings/strcat.h"
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/bpf_skeletons/skeleton_network_bpf.h"
#include "secagentd/common.h"
#include "secagentd/metrics_sender.h"

namespace secagentd {

// Directory with min_core_btf payloads. Must match the ebuild.
constexpr char kMinCoreBtfDir[] = "/usr/share/btf/secagentd/";

// The following callback definitions must have void return type since they will
// bind to an object method.
using BpfEventCb = base::RepeatingCallback<void(const bpf::cros_event&)>;
using BpfEventAvailableCb = base::RepeatingCallback<void()>;

// The callbacks a BPF plugins are required to provide.
struct BpfCallbacks {
  // The callback responsible for handling a ring buffer security event.
  BpfEventCb ring_buffer_event_callback;
  // The callback that handles when any ring buffer has data ready for
  // consumption (reading).
  BpfEventAvailableCb ring_buffer_read_ready_callback;
};

class BpfSkeletonInterface {
 public:
  explicit BpfSkeletonInterface(const BpfSkeletonInterface&) = delete;
  BpfSkeletonInterface& operator=(const BpfSkeletonInterface&) = delete;
  virtual ~BpfSkeletonInterface() = default;
  // Consume one or more events from a BPF ring buffer, ignoring whether a ring
  // buffer has notified that data is available for read.
  virtual int ConsumeEvent() = 0;

 protected:
  friend class BpfSkeletonFactory;
  friend class NetworkBpfSkeleton;
  BpfSkeletonInterface() = default;

  virtual std::pair<absl::Status, metrics::BpfAttachResult> LoadAndAttach() = 0;

  // Register callbacks to handle:
  // 1 - When a security event from a ring buffer has been consumed and is
  // available for further processing.
  // 2 - When a ring buffer has data available for reading.
  virtual void RegisterCallbacks(BpfCallbacks cbs) = 0;
};

template <typename T>
struct SkeletonCallbacks {
  base::RepeatingCallback<void(T* obj)> destroy;
  base::RepeatingCallback<T*()> open;
  base::RepeatingCallback<T*(const struct bpf_object_open_opts* opts)>
      open_opts;
};

template <typename SkeletonType>
class BpfSkeleton : public BpfSkeletonInterface {
 public:
  BpfSkeleton(std::string_view plugin_name,
              const SkeletonCallbacks<SkeletonType>& skel_cb)
      : name_(plugin_name), skel_cbs_(skel_cb) {}
  ~BpfSkeleton() override {
    // The file descriptor being watched must outlive the controller.
    // Force rb_watch_readable_ destruction before closing fd.
    rb_watch_readable_ = nullptr;
    if (rb_ != nullptr) {
      // Free and close all ring buffer fds.
      ring_buffer__free(rb_);
    }
    if (skel_ != nullptr) {
      skel_cbs_.destroy.Run(skel_);
    }
  }
  int ConsumeEvent() override {
    if (rb_ == nullptr) {
      return -1;
    }
    return ring_buffer__consume(rb_);
  }

 protected:
  friend class BpfSkeletonFactory;
  friend class NetworkBpfSkeleton;
  std::pair<absl::Status, metrics::BpfAttachResult> LoadAndAttach() override {
    if (callbacks_.ring_buffer_event_callback.is_null() ||
        callbacks_.ring_buffer_read_ready_callback.is_null()) {
      return std::make_pair(
          absl::InternalError(base::StrCat(
              {name_,
               ": LoadAndAttach failed, one or more provided callbacks "
               "are null."})),
          metrics::BpfAttachResult(-1));
    }
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
#if defined(USE_MIN_CORE_BTF) && USE_MIN_CORE_BTF == 1
    // Ask libbpf to load a BTF that's tailored specifically to this BPF. Note
    // that this is more of a suggestion because libbpf will silently ignore the
    // request if it doesn't like the type of BPF or its access patterns.
    const std::string btf_path =
        base::StrCat({secagentd::kMinCoreBtfDir, name_, "_bpf.min.btf"});
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
                        .btf_custom_path = btf_path.c_str());
    skel_ = skel_cbs_.open_opts.Run(&open_opts);
#else
    // Let libbpf extract BTF from /sys/kernel/btf/vmlinux.
    skel_ = skel_cbs_.open.Run();
#endif  // USE_MIN_CORE_BTF

    if (!skel_) {
      return std::make_pair(absl::InternalError(base::StrCat(
                                {name_, "BPF skeleton failed to open."})),
                            metrics::BpfAttachResult::kErrorOpen);
    }
    if (bpf_object__load_skeleton(skel_->skeleton)) {
      return std::make_pair(
          absl::InternalError(base::StrCat(
              {name_, ": application failed loading and verification."})),
          metrics::BpfAttachResult::kErrorLoad);
    }

    if (bpf_object__attach_skeleton(skel_->skeleton)) {
      return std::make_pair(absl::InternalError(base::StrCat(
                                {name_, ": program failed to attach."})),
                            metrics::BpfAttachResult::kErrorAttach);
    }

    int map_fd = bpf_map__fd(skel_->maps.rb);
    int epoll_fd{-1};

    // ring_buffer__new will fail with an invalid fd but we explicitly check
    // anyways for code clarity.
    if (map_fd >= 0) {
      rb_ = ring_buffer__new(
          map_fd, indirect_c_callback,
          static_cast<void*>(&callbacks_.ring_buffer_event_callback), nullptr);
      epoll_fd = ring_buffer__epoll_fd(rb_);
    }

    if (map_fd < 0 || !rb_ || epoll_fd < 0) {
      return std::make_pair(absl::InternalError(base::StrCat(
                                {name_, ": Ring buffer creation failed."})),
                            metrics::BpfAttachResult::kErrorRingBuffer);
    }

    rb_watch_readable_ = base::FileDescriptorWatcher::WatchReadable(
        epoll_fd, callbacks_.ring_buffer_read_ready_callback);
    return std::make_pair(absl::OkStatus(), metrics::BpfAttachResult::kSuccess);
  }
  void RegisterCallbacks(BpfCallbacks cbs) override { callbacks_ = cbs; }
  SkeletonType* skel_{nullptr};
  BpfCallbacks callbacks_;

 private:
  std::string name_;
  const SkeletonCallbacks<SkeletonType> skel_cbs_;
  struct ring_buffer* rb_{nullptr};
  std::unique_ptr<base::FileDescriptorWatcher::Controller> rb_watch_readable_;
};

class NetworkBpfSkeleton : public BpfSkeletonInterface {
 public:
  explicit NetworkBpfSkeleton(uint32_t batch_interval_s);
  int ConsumeEvent() override;

 protected:
  std::pair<absl::Status, metrics::BpfAttachResult> LoadAndAttach() override;
  void ScanFlowMap();
  std::unordered_set<uint64_t> GetActiveSocketsSet();
  void RegisterCallbacks(BpfCallbacks cbs) override;

 private:
  uint32_t batch_interval_s_;
  std::unique_ptr<BpfSkeleton<network_bpf>> default_bpf_skeleton_;
  // Timer to periodically scan the BPF map and generate synthetic flow
  // events.
  base::RepeatingTimer scan_bpf_maps_timer_;
  base::WeakPtrFactory<NetworkBpfSkeleton> weak_ptr_factory_;
};

class BpfSkeletonFactoryInterface
    : public ::base::RefCounted<BpfSkeletonFactoryInterface> {
 public:
  struct SkeletonInjections {
    std::unique_ptr<BpfSkeletonInterface> process;
    std::unique_ptr<BpfSkeletonInterface> network;
  };

  // Creates a BPF Handler class that loads and attaches a BPF application.
  // The passed in callback will be invoked when an event is available from the
  // BPF application.
  virtual std::unique_ptr<BpfSkeletonInterface> Create(
      Types::BpfSkeleton type, BpfCallbacks cbs, uint32_t batch_interval_s) = 0;
  virtual ~BpfSkeletonFactoryInterface() = default;
};

class BpfSkeletonFactory : public BpfSkeletonFactoryInterface {
 public:
  BpfSkeletonFactory() = default;
  explicit BpfSkeletonFactory(SkeletonInjections di) : di_(std::move(di)) {}

  std::unique_ptr<BpfSkeletonInterface> Create(
      Types::BpfSkeleton type,
      BpfCallbacks cbs,
      uint32_t batch_interval_s) override;

 private:
  SkeletonInjections di_;
};

}  //  namespace secagentd
#endif  // SECAGENTD_BPF_SKELETON_WRAPPERS_H_
