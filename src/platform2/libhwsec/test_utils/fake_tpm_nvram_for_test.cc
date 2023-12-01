// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/test_utils/fake_tpm_nvram_for_test.h"

#include <memory>
#include <string>
#include <vector>

#include <absl/container/flat_hash_map.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

using testing::_;

using Attributes = std::bitset<tpm_manager::NvramSpaceAttribute_ARRAYSIZE>;

namespace hwsec {

namespace {

template <typename T>
Attributes ConvertAttributes(const T& attributs) {
  Attributes result;
  for (auto attribute : attributs) {
    result[attribute] = true;
  }
  return result;
}

}  // namespace

struct FakeTpmNvramForTest::SpaceInfo {
  bool read_lock = false;
  bool write_lock = false;
  std::string data;
  std::string auth_value;
  Attributes attributes;
};

FakeTpmNvramForTest::FakeTpmNvramForTest()
    : tpm_nvram_(std::make_unique<
                 testing::NiceMock<org::chromium::TpmNvramProxyMock>>()) {}

FakeTpmNvramForTest::~FakeTpmNvramForTest() = default;

bool FakeTpmNvramForTest::Init() {
  ON_CALL(*tpm_nvram_, DefineSpace(_, _, _, _))
      .WillByDefault([this](const tpm_manager::DefineSpaceRequest& request,
                            tpm_manager::DefineSpaceReply* reply, auto&&,
                            auto&&) {
        if (space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_ALREADY_EXISTS);
          return true;
        }

        space_info_[request.index()] = SpaceInfo{
            .data = std::string(request.size(), 0),
            .auth_value = request.authorization_value(),
            .attributes = ConvertAttributes(request.attributes()),
        };

        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        return true;
      });

  ON_CALL(*tpm_nvram_, DestroySpace(_, _, _, _))
      .WillByDefault([this](const tpm_manager::DestroySpaceRequest& request,
                            tpm_manager::DestroySpaceReply* reply, auto&&,
                            auto&&) {
        if (!space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
          return true;
        }

        if (space_info_[request.index()]
                .attributes[tpm_manager::NVRAM_PLATFORM_CREATE]) {
          reply->set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
          return true;
        }

        space_info_.erase(request.index());
        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        return true;
      });

  ON_CALL(*tpm_nvram_, WriteSpace(_, _, _, _))
      .WillByDefault([this](const tpm_manager::WriteSpaceRequest& request,
                            tpm_manager::WriteSpaceReply* reply, auto&&,
                            auto&&) {
        if (!space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
          return true;
        }

        if (space_info_[request.index()].write_lock) {
          reply->set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
          return true;
        }

        if (space_info_[request.index()]
                .attributes[tpm_manager::NVRAM_OWNER_WRITE] !=
            request.use_owner_authorization()) {
          reply->set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
          return true;
        }

        if (space_info_[request.index()].auth_value !=
            request.authorization_value()) {
          reply->set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
          return true;
        }

        space_info_[request.index()].data = request.data();
        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        return true;
      });

  ON_CALL(*tpm_nvram_, ReadSpace(_, _, _, _))
      .WillByDefault([this](const tpm_manager::ReadSpaceRequest& request,
                            tpm_manager::ReadSpaceReply* reply, auto&&,
                            auto&&) {
        if (!space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
          return true;
        }

        if (space_info_[request.index()].read_lock) {
          reply->set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
          return true;
        }

        if (space_info_[request.index()]
                .attributes[tpm_manager::NVRAM_OWNER_READ] !=
            request.use_owner_authorization()) {
          reply->set_result(tpm_manager::NVRAM_RESULT_OPERATION_DISABLED);
          return true;
        }

        if (space_info_[request.index()].auth_value !=
            request.authorization_value()) {
          reply->set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
          return true;
        }

        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        reply->set_data(space_info_[request.index()].data);
        return true;
      });

  ON_CALL(*tpm_nvram_, LockSpace(_, _, _, _))
      .WillByDefault([this](const tpm_manager::LockSpaceRequest& request,
                            tpm_manager::LockSpaceReply* reply, auto&&,
                            auto&&) {
        if (!space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
          return true;
        }

        if (space_info_[request.index()].auth_value !=
            request.authorization_value()) {
          reply->set_result(tpm_manager::NVRAM_RESULT_ACCESS_DENIED);
          return true;
        }

        if (request.lock_read()) {
          space_info_[request.index()].read_lock = true;
        }

        if (request.lock_write()) {
          space_info_[request.index()].write_lock = true;
        }

        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        return true;
      });

  ON_CALL(*tpm_nvram_, ListSpaces(_, _, _, _))
      .WillByDefault([this](const tpm_manager::ListSpacesRequest& request,
                            tpm_manager::ListSpacesReply* reply, auto&&,
                            auto&&) {
        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        for (const auto& [index, info] : space_info_) {
          reply->add_index_list(index);
        }
        return true;
      });

  ON_CALL(*tpm_nvram_, GetSpaceInfo(_, _, _, _))
      .WillByDefault([this](const tpm_manager::GetSpaceInfoRequest& request,
                            tpm_manager::GetSpaceInfoReply* reply, auto&&,
                            auto&&) {
        if (!space_info_.count(request.index())) {
          reply->set_result(tpm_manager::NVRAM_RESULT_SPACE_DOES_NOT_EXIST);
          return true;
        }

        SpaceInfo& info = space_info_[request.index()];
        reply->set_result(tpm_manager::NVRAM_RESULT_SUCCESS);
        reply->set_size(info.data.size());
        reply->set_is_read_locked(info.read_lock);
        reply->set_is_write_locked(info.write_lock);
        for (int i = 0; i < info.attributes.size(); i++) {
          if (info.attributes[i]) {
            reply->add_attributes(
                static_cast<tpm_manager::NvramSpaceAttribute>(i));
          }
        }
        return true;
      });

  return true;
}

testing::NiceMock<org::chromium::TpmNvramProxyMock>*
FakeTpmNvramForTest::GetMock() {
  return tpm_nvram_.get();
}

bool FakeTpmNvramForTest::DefinePlatformCreateSpace(uint32_t index,
                                                    uint32_t size) {
  if (space_info_.count(index)) {
    return false;
  }

  space_info_[index] = SpaceInfo{
      .data = std::string(size, 0),
      .auth_value = "",
      .attributes = (1ULL << tpm_manager::NVRAM_PLATFORM_CREATE) |
                    (1ULL << tpm_manager::NVRAM_READ_AUTHORIZATION) |
                    (1ULL << tpm_manager::NVRAM_WRITE_AUTHORIZATION),
  };
  return true;
}

}  // namespace hwsec
