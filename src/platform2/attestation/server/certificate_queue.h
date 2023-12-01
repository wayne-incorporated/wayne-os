// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_CERTIFICATE_QUEUE_H_
#define ATTESTATION_SERVER_CERTIFICATE_QUEUE_H_

#include <memory>
#include <unordered_map>
#include <vector>

#include "attestation/server/attestation_flow.h"

namespace attestation {

// This class maintains a collection of attestation flow data entries of
// |GetCertificateRequest|s. In this class, the entries of the same |aca_type|,
// |username|, and |key_label| are considered as aliases. See the docs of public
// APIs for more information.
class CertificateQueue {
 public:
  enum class PushResult {
    kSuccess,
    kAliasLimit,
    kInconsistentConfig,
  };

  // Constructs an instance where |alias_limit| is the size limit for each
  // alias.
  explicit CertificateQueue(size_t alias_limit);
  ~CertificateQueue() = default;

  // Puts |data| into the queue. Returns |kSuccess| if the operation succeeds.
  // Otherwise there are 2 categories of failures as below: 1) if too many
  // aliases of |data| are already in the queue (i.e., >= |alias_limit_|),
  // returns |kAliasLimit|; or 2) if any field of |data| doesn't match its
  // alias(es) (e.g., key type, profile,...), returns |kInconsistentProfile|.
  PushResult Push(const std::shared_ptr<AttestationFlowData>& data);

  // Checks if there is any alias of |data| in the queue already.
  bool HasAnyAlias(const std::shared_ptr<AttestationFlowData>& data) const;

  // Clears the returns the aliases of |data| in the queue.
  std::vector<std::shared_ptr<AttestationFlowData>> PopAllAliases(
      const std::shared_ptr<AttestationFlowData>& data);

 private:
  // Size limit for each alias group.
  const size_t alias_limit_;

  // Custom definition of hash function for |data| based on the |username| and
  // |key_label| in the |GetCertificateRequest|.
  // Note that the definition of alias includes the same |aca_type| in the
  // request, but in practice it is not supposed to happen so we don't count
  // |aca_type| as an input of the hash function. This decision is
  // also driven by the fact that standard library doesn't provide a standard
  // way to combine hashes. Thus, we sacrifice the accuracy for runtime
  // efficiency IRL and simplicity.
  class DataHash {
   public:
    size_t operator()(const std::shared_ptr<AttestationFlowData>& data) const;
  };
  // Comparator class that tells if 2 |AttestationFlowData|s' |username|,
  // |key_label|, and |aca_type| are all identical.
  class DataEqual {
   public:
    bool operator()(const std::shared_ptr<AttestationFlowData>& data1,
                    const std::shared_ptr<AttestationFlowData>& data2) const;
  };

  // Hash table that stores |AttestationFlowData|s. See |DataHash| and
  // |DataEqual| more information.
  std::unordered_map<std::shared_ptr<AttestationFlowData>,
                     std::vector<std::shared_ptr<AttestationFlowData>>,
                     DataHash,
                     DataEqual>
      table_;
};

// Synchronized implementation of |CertificateQueue|; behind the scene it just
// wraps all the public interfaces of |CertificateQueue| with the same |mutex_|
// instance.
class SynchronizedCertificateQueue {
 public:
  explicit SynchronizedCertificateQueue(size_t alias_limit)
      : certificate_queue_(alias_limit) {}
  ~SynchronizedCertificateQueue() = default;

  CertificateQueue::PushResult Push(
      const std::shared_ptr<AttestationFlowData>& data) {
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    return certificate_queue_.Push(data);
  }

  bool HasAnyAlias(const std::shared_ptr<AttestationFlowData>& data) const {
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    return certificate_queue_.HasAnyAlias(data);
  }

  std::vector<std::shared_ptr<AttestationFlowData>> PopAllAliases(
      const std::shared_ptr<AttestationFlowData>& data) {
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    return certificate_queue_.PopAllAliases(data);
  }

 private:
  CertificateQueue certificate_queue_;
  mutable std::mutex mutex_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_CERTIFICATE_QUEUE_H_
