// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_COMPRESSION_TEST_COMPRESSION_MODULE_H_
#define MISSIVE_COMPRESSION_TEST_COMPRESSION_MODULE_H_

#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/string_piece.h>

#include "missive/compression/compression_module.h"
#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/statusor.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace reporting::test {

// An |CompressionModuleInterface| that does no compression.
class TestCompressionModuleStrict : public CompressionModule {
 public:
  TestCompressionModuleStrict();

  MOCK_METHOD(void,
              CompressRecord,
              (std::string record,
               scoped_refptr<ResourceManager> memory_resource,
               base::OnceCallback<void(
                   std::string, std::optional<CompressionInformation>)> cb),
              (const override));

 protected:
  ~TestCompressionModuleStrict() override;
};

// Most of the time no need to log uninterested calls to |EncryptRecord|.
typedef ::testing::NiceMock<TestCompressionModuleStrict> TestCompressionModule;

}  // namespace reporting::test

#endif  // MISSIVE_COMPRESSION_TEST_COMPRESSION_MODULE_H_
