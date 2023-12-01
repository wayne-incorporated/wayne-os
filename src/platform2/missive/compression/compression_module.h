// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_COMPRESSION_COMPRESSION_MODULE_H_
#define MISSIVE_COMPRESSION_COMPRESSION_MODULE_H_

#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_piece.h>

#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/dynamic_flag.h"

namespace reporting {

class CompressionModule : public DynamicFlag,
                          public base::RefCountedThreadSafe<CompressionModule> {
 public:
  // Not copyable or movable
  CompressionModule(const CompressionModule& other) = delete;
  CompressionModule& operator=(const CompressionModule& other) = delete;

  // Factory method creates |CompressionModule| object.
  static scoped_refptr<CompressionModule> Create(
      bool is_enabled,
      uint64_t compression_threshold,
      CompressionInformation::CompressionAlgorithm compression_type);

  // CompressRecord will attempt to compress the provided |record| and respond
  // with the callback. On success the returned std::string sink will
  // contain a compressed WrappedRecord string. The sink string then can be
  // further updated by the caller. std::string is used instead of
  // base::StringPiece because ownership is taken of |record| through
  // std::move(record).
  void CompressRecord(
      std::string record,
      scoped_refptr<ResourceManager> memory_resource,
      base::OnceCallback<void(std::string,
                              std::optional<CompressionInformation>)> cb) const;

 protected:
  // Constructor can only be called by |Create| factory method.
  CompressionModule(
      bool is_enabled,
      uint64_t compression_threshold,
      CompressionInformation::CompressionAlgorithm compression_type);

  // Refcounted object must have destructor declared protected or private.
  ~CompressionModule() override;

 private:
  friend base::RefCountedThreadSafe<CompressionModule>;

  // Compresses a record using snappy
  void CompressRecordSnappy(
      std::string record,
      base::OnceCallback<void(std::string,
                              std::optional<CompressionInformation>)> cb) const;

  // Compression type to use.
  const CompressionInformation::CompressionAlgorithm compression_type_;

  // Minimum compression threshold (in bytes) for when a record will be
  // compressed
  const uint64_t compression_threshold_;
};

}  // namespace reporting

#endif  // MISSIVE_COMPRESSION_COMPRESSION_MODULE_H_
