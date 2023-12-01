// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_CHAPS_CRYPTO_OPERATION_H_
#define ARC_KEYMASTER_CONTEXT_CHAPS_CRYPTO_OPERATION_H_

#include <memory>
#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>

#include "arc/keymaster/context/context_adaptor.h"
#include "arc/keymaster/context/crypto_operation.h"

namespace arc {
namespace keymaster {
namespace context {

class ChapsClient;

extern const MechanismDescription kCkmRsaPkcsSign;
extern const MechanismDescription kCkmMd5RsaPkcsSign;
extern const MechanismDescription kCkmSha1RsaPkcsSign;
extern const MechanismDescription kCkmSha256RsaPkcsSign;
extern const MechanismDescription kCkmSha384RsaPkcsSign;
extern const MechanismDescription kCkmSha512RsaPkcsSign;

// Implement operations by forwarding them to Chaps via |ChapsClient|.
class ChapsCryptoOperation : public CryptoOperation {
 public:
  ChapsCryptoOperation(base::WeakPtr<ContextAdaptor> context_adaptor,
                       ContextAdaptor::Slot slot,
                       const std::string& label,
                       const brillo::Blob& id);
  ~ChapsCryptoOperation() override;
  // Not copyable nor assignable.
  ChapsCryptoOperation(const ChapsCryptoOperation&) = delete;
  ChapsCryptoOperation& operator=(const ChapsCryptoOperation&) = delete;

  // CryptoOperation overrides:
  std::optional<uint64_t> Begin(MechanismDescription description) override;
  std::optional<brillo::Blob> Update(const brillo::Blob& input) override;
  std::optional<brillo::Blob> Finish() override;
  bool Abort() override;

  bool IsSupportedMechanism(MechanismDescription description) const override;

 private:
  const base::WeakPtr<ContextAdaptor> context_adaptor_;

  // Chaps slot where the key is stored.
  const ContextAdaptor::Slot slot_;
  // Key label and ID in Chaps, correspond to PKCS#11 CKA_LABEL and CKA_ID.
  const std::string label_;
  const brillo::Blob id_;

  // Chaps client is allocated in Begin, and released in Finish/Abort.
  std::unique_ptr<ChapsClient> chaps_;
};

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_CHAPS_CRYPTO_OPERATION_H_
