// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_CRYPTO_OPERATION_H_
#define ARC_KEYMASTER_CONTEXT_CRYPTO_OPERATION_H_

#include <memory>
#include <optional>
#include <string>

#include <base/check.h>
#include <brillo/secure_blob.h>

namespace arc {
namespace keymaster {
namespace context {

// Comprehensive list of cryptographic operations supported for Chrome OS keys.
enum class OperationType {
  kSign,
  kUnsupported,
};

// Comprehensive list of algorithms supported for Chrome OS keys.
enum class Algorithm {
  kRsa,
  kUnsupported,
};

// Comprehensive list of digests supported for Chrome OS keys.
enum class Digest {
  kMd5,
  kSha1,
  kSha256,
  kSha384,
  kSha512,
  kNone,
  kUnsupported,
};

// Comprehensive list of paddings supported for Chrome OS keys.
enum class Padding {
  // Block cipher padding method detailed in PKCS #7. Android uses PKCS #5.
  // Both work the same way, except that PKCS #5 is defined for 8-byte block
  // sizes, while PKCS #7 is defined over blocks of sizes in [1, 255] bytes.
  kPkcs7,
  // RSA padding detailed in PKCS #1 v1.5.
  kPkcs1,
  kNone,
  kUnsupported,
};

// Comprehensive list of block modes supported for Chrome OS keys.
enum class BlockMode {
  kCbc,
  kNone,
  kUnsupported,
};

// Contains the full description of an encryption mechanism. Contains all
// parameters necessary to determine exactly how to execute a cryptographic
// operation.
struct MechanismDescription {
  constexpr MechanismDescription(OperationType type,
                                 Algorithm algorithm,
                                 Digest digest,
                                 Padding padding,
                                 BlockMode block_mode)
      : type(type),
        algorithm(algorithm),
        digest(digest),
        padding(padding),
        block_mode(block_mode) {}

  ~MechanismDescription() = default;

  MechanismDescription(const MechanismDescription& other);

  MechanismDescription& operator=(const MechanismDescription& other);

  bool operator==(const MechanismDescription& other) const;

  bool operator<(const MechanismDescription& other) const;

  OperationType type;
  Algorithm algorithm;
  Digest digest;
  Padding padding;
  BlockMode block_mode;
};

// Interface for cryptographic operations.
//
// Proxies for key sources (e.g. chaps) should each provide an
// implementation.
class CryptoOperation {
 public:
  virtual ~CryptoOperation();
  // Not copyable nor assignable.
  CryptoOperation(const CryptoOperation&) = delete;
  CryptoOperation& operator=(const CryptoOperation&) = delete;

  // Initializes any necessary state.
  //
  // Returns a handle to identify this operation, and |nullopt| when this
  // operation is not supported or there's an error during execution.
  virtual std::optional<uint64_t> Begin(MechanismDescription description) = 0;

  // Updates this operation with some |input|.
  //
  // Returns an output blob, or |nullopt| in case of error. The returned blob
  // may be empty if there's no output to be produced, e.g. in a signature
  // operation.
  virtual std::optional<brillo::Blob> Update(const brillo::Blob& input) = 0;

  // Finishes this operation.
  //
  // Returns the final output blob, or |nullopt| in case of error. The returned
  // blob may be empty if no output was produced, e.g. in an encrypt operation
  // where all output has already been produced through |Update|.
  virtual std::optional<brillo::Blob> Finish() = 0;

  // Aborts this operation.
  //
  // Returns |true| if the operation was aborted successfully.
  virtual bool Abort() = 0;

  // Returns true if this |description| is supported by the implementation.
  virtual bool IsSupportedMechanism(MechanismDescription description) const = 0;

  // Returns the description for this operation. Must be called after
  // |set_description|.
  const MechanismDescription& description() const {
    DCHECK(description_.has_value()) << "Must call set_description first";
    return description_.value();
  }

  void set_description(MechanismDescription description) {
    description_.emplace(description);
  }

 protected:
  CryptoOperation();

 private:
  std::optional<MechanismDescription> description_;
};

std::ostream& operator<<(std::ostream& os,
                         MechanismDescription const& description);

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_CRYPTO_OPERATION_H_
