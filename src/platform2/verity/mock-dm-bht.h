/*
 * Copyright 2022 The ChromiumOS Authors <chromium-os-dev@chromium.org>
 *
 * Device-Mapper block hash tree interface.
 * See Documentation/device-mapper/dm-bht.txt for details.
 *
 * This file is released under the GPLv2.
 */
#ifndef VERITY_MOCK_DM_BHT_H_
#define VERITY_MOCK_DM_BHT_H_

#include <string>

namespace verity {

class MockDmBht : public DmBhtInterface {
 public:
  MockDmBht() = default;

  MockDmBht(const MockDmBht&) = delete;
  MockDmBht& operator=(const MockDmBht&) = delete;

  MOCK_METHOD(int,
              Create,
              (unsigned int blocksize, std::string alg),
              (override));
  MOCK_METHOD(void, SetReadCallback, (dm_bht_callback callback), (override));
  MOCK_METHOD(void, SetSalt, (std::string hexsalt), (override));
  MOCK_METHOD(void, SetBuffer, (void* buffer), (override));
  MOCK_METHOD(sector_t, Sectors, (), (override));
  MOCK_METHOD(unsigned int, DigestSize, (), (override));
  MOCK_METHOD(int,
              StoreBlock,
              (unsigned int block, uint8_t* block_data),
              (override));
  MOCK_METHOD(int, Compute, (), (override));
  MOCK_METHOD(void,
              HexDigest,
              (uint8_t * hexdigest, int available),
              (override));
};

}  // namespace verity

#endif  // VERITY_MOCK_DM_BHT_H_
