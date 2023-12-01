// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_BATCH_SENDER_H_
#define SECAGENTD_BATCH_SENDER_H_

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/lock.h"
#include "base/timer/timer.h"
#include "secagentd/message_sender.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd {

// KeyType: Return type of the "KeyDerivation" method that's used to uniquely
// identify and query queued messages. E.g the UUID of a process or the
// Community ID of a network event.
//
// XdrMessage: The larger composed or batched message type.
//
// AtomicVariantMessage: Type of the individual variant that XdrMessage is
// composed of.
template <typename KeyType, typename XdrMessage, typename AtomicVariantMessage>
class BatchSenderInterface {
 public:
  using VisitCallback = base::OnceCallback<void(AtomicVariantMessage*)>;

  virtual ~BatchSenderInterface() = default;

  // Starts internal timers.
  virtual void Start() = 0;
  // Enqueues a single atomic event. Will fill out the common fields.
  virtual void Enqueue(std::unique_ptr<AtomicVariantMessage> batched_event) = 0;
  // Applies the callback to an arbitrary message matching given variant type
  // and key. Important: The callback must not change any fields that are used
  // by KeyDerive because that isn't handled properly yet.
  virtual bool Visit(
      typename AtomicVariantMessage::VariantTypeCase variant_type,
      const KeyType& key,
      VisitCallback cb) = 0;
};

template <typename KeyType, typename XdrMessage, typename AtomicVariantMessage>
class BatchSender
    : public BatchSenderInterface<KeyType, XdrMessage, AtomicVariantMessage> {
 public:
  using KeyDerive =
      base::RepeatingCallback<KeyType(const AtomicVariantMessage&)>;
  using VisitCallback = base::OnceCallback<void(AtomicVariantMessage*)>;

  static constexpr size_t kMaxMessageSizeBytes = 8 * 1024 * 1024;

  BatchSender(KeyDerive kd,
              scoped_refptr<secagentd::MessageSenderInterface> message_sender,
              reporting::Destination destination,
              uint32_t batch_interval_s)
      : weak_ptr_factory_(this),
        kd_(std::move(kd)),
        message_sender_(message_sender),
        destination_(destination),
        batch_interval_s_(batch_interval_s) {}

  void Start() override {
    batch_timer_.Start(FROM_HERE,
                       base::Seconds(std::max(batch_interval_s_, 1u)),
                       base::BindRepeating(&BatchSender::Flush,
                                           weak_ptr_factory_.GetWeakPtr()));
  }
  bool Visit(typename AtomicVariantMessage::VariantTypeCase variant_type,
             const KeyType& key,
             VisitCallback cb) override {
    base::AutoLock lock(events_lock_);
    auto it = lookup_map_.find(std::make_pair(variant_type, key));
    if (it != lookup_map_.end()) {
      events_byte_size_ -= it->second->ByteSizeLong();
      std::move(cb).Run(it->second);
      events_byte_size_ += it->second->ByteSizeLong();
      return true;
    }
    cb.Reset();
    return false;
  }

  void Enqueue(std::unique_ptr<AtomicVariantMessage> atomic_event) override {
    atomic_event->mutable_common()->set_create_timestamp_us(
        base::Time::Now().ToJavaTime() *
        base::Time::kMicrosecondsPerMillisecond);
    base::AutoLock lock(events_lock_);
    size_t event_byte_size = atomic_event->ByteSizeLong();
    // Reserve ~10% for overhead of packing these events into the larger
    // message.
    if (events_byte_size_ + event_byte_size >= kMaxMessageSizeBytes * 0.9) {
      base::AutoUnlock unlock(events_lock_);
      Flush();
    }
    lookup_map_.insert(
        std::make_pair(std::make_pair(atomic_event->variant_type_case(),
                                      kd_.Run(*atomic_event)),
                       atomic_event.get()));
    events_byte_size_ += event_byte_size;
    events_.emplace_back(std::move(atomic_event));
  }

 protected:
  void Flush() {
    if (events_byte_size_) {
      base::AutoLock lock(events_lock_);
      VLOG(1) << "Flushing Batch for Destination " << destination_
              << ". Batch size = " << events_.size() << " (~"
              << events_byte_size_ << " bytes)";
      lookup_map_.clear();
      auto xdr_proto = std::make_unique<XdrMessage>();
      for (auto& event : events_) {
        xdr_proto->add_batched_events()->Swap(event.get());
      }
      message_sender_->SendMessage(destination_, xdr_proto->mutable_common(),
                                   std::move(xdr_proto), std::nullopt);
      events_.clear();
      events_byte_size_ = 0;
    }
    // Automatically re-fires timer after the same delay.
    batch_timer_.Reset();
  }

  base::WeakPtrFactory<BatchSender> weak_ptr_factory_;
  KeyDerive kd_;
  scoped_refptr<secagentd::MessageSenderInterface> message_sender_;
  const reporting::Destination destination_;
  uint32_t batch_interval_s_;
  base::RetainingOneShotTimer batch_timer_;
  base::Lock events_lock_;
  // Lookup Key -> &event for visitation.
  absl::flat_hash_map<
      std::pair<typename AtomicVariantMessage::VariantTypeCase, KeyType>,
      AtomicVariantMessage*>
      lookup_map_;
  // Vector of currently enqueued (atomic) events.
  std::vector<std::unique_ptr<AtomicVariantMessage>> events_;
  // Running total serialized size of currently enqueued events.
  size_t events_byte_size_ = 0;
};

}  // namespace secagentd

#endif  // SECAGENTD_BATCH_SENDER_H_
