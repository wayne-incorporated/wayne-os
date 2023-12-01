// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/compression/test_compression_module.h"

#include <optional>
#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/string_piece.h>

#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/statusor.h"

using ::testing::Invoke;

namespace reporting::test {

constexpr size_t kCompressionThreshold = 2;
const CompressionInformation::CompressionAlgorithm kCompressionType =
    CompressionInformation::COMPRESSION_NONE;

TestCompressionModuleStrict::TestCompressionModuleStrict()
    : CompressionModule(
          /*is_enabled=*/true, kCompressionThreshold, kCompressionType) {
  ON_CALL(*this, CompressRecord)
      .WillByDefault(Invoke(
          [](std::string record,
             scoped_refptr<ResourceManager> resource_manager,
             base::OnceCallback<void(
                 std::string, std::optional<CompressionInformation>)> cb) {
            // compression_info is not set.
            std::move(cb).Run(record, std::nullopt);
          }));
}

TestCompressionModuleStrict::~TestCompressionModuleStrict() = default;

}  // namespace reporting::test
