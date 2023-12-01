// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/rar_mounter.h"

#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/metrics.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"

namespace cros_disks {

namespace {

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::SizeIs;

class FakeSandboxedProcessFactory : public SandboxedProcessFactory {
 public:
  std::unique_ptr<SandboxedProcess> CreateSandboxedProcess() const {
    return std::make_unique<FakeSandboxedProcess>();
  }
};

}  // namespace

class RarMounterTest : public testing::Test {
 protected:
  Metrics metrics_;
  MockPlatform platform_;
  brillo::ProcessReaper reaper_;
  const RarMounter mounter_{&platform_, &reaper_, &metrics_,
                            std::make_unique<FakeSandboxedProcessFactory>()};
};

TEST_F(RarMounterTest, FileSystemType) {
  EXPECT_EQ(mounter_.filesystem_type(), "rar");
}

TEST_F(RarMounterTest, Increment) {
  std::string s;
  const auto inc = [&s] { return RarMounter::Increment(s.begin(), s.end()); };

  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "");

  s = "0";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "1");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "2");

  s = "8";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "9");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "0");

  s = "00";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "01");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "02");

  s = "09";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "10");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "11");

  s = "98";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "99");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "00");

  s = "000";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "001");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "002");

  s = "009";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "010");

  s = "099";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "100");

  s = "999";
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "000");

  s = "a";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "b");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "c");

  s = "y";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "z");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "a");

  s = "A";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "B");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "C");

  s = "Y";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "Z");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "A");

  s = "r00";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "r01");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "r02");

  s = "r98";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "r99");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "s00");

  s = "z98";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "z99");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "a00");

  s = "R00";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "R01");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "R02");

  s = "R98";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "R99");
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "S00");

  s = "Z98";
  EXPECT_TRUE(inc());
  EXPECT_EQ(s, "Z99");
  EXPECT_FALSE(inc());
  EXPECT_EQ(s, "A00");
}

TEST_F(RarMounterTest, ParseDigits) {
  const auto ir = [](const size_t begin, const size_t end) {
    return RarMounter::IndexRange{begin, end};
  };

  EXPECT_THAT(RarMounter::ParseDigits(""), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("0"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits(".rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("part.rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits(".part.rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("blah.part.rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("blah0.part.rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("/blah.part.rar"), IsEmpty());
  EXPECT_THAT(RarMounter::ParseDigits("0.rar"), ir(0, 1));
  EXPECT_THAT(RarMounter::ParseDigits("part0.rar"), ir(4, 5));
  EXPECT_EQ(RarMounter::ParseDigits(".part0.rar"), ir(5, 6));
  EXPECT_EQ(RarMounter::ParseDigits("blah.part0.rar"), ir(9, 10));
  EXPECT_EQ(RarMounter::ParseDigits("/blah.part0.rar"), ir(10, 11));
  EXPECT_EQ(RarMounter::ParseDigits("/some/path/blah.part0.rar"), ir(20, 21));
  EXPECT_EQ(RarMounter::ParseDigits(".part9.rar"), ir(5, 6));
  EXPECT_EQ(RarMounter::ParseDigits("blah.part9.rar"), ir(9, 10));
  EXPECT_EQ(RarMounter::ParseDigits("/blah.part9.rar"), ir(10, 11));
  EXPECT_EQ(RarMounter::ParseDigits("/some/path/blah.part9.rar"), ir(20, 21));
  EXPECT_EQ(RarMounter::ParseDigits(".part2468097531.rar"), ir(5, 15));
  EXPECT_EQ(RarMounter::ParseDigits("blah.part2468097531.rar"), ir(9, 19));
  EXPECT_EQ(RarMounter::ParseDigits("/blah.part2468097531.rar"), ir(10, 20));
  EXPECT_EQ(RarMounter::ParseDigits("/some/path/blah.part2468097531.rar"),
            ir(20, 30));
  EXPECT_EQ(RarMounter::ParseDigits("Blah.Part0.Rar"), ir(9, 10));
  EXPECT_EQ(RarMounter::ParseDigits("BLAH.PART0.RAR"), ir(9, 10));
}

TEST_F(RarMounterTest, GetBindPathsWithOldNamingScheme) {
  const RarMounter& m = mounter_;
  EXPECT_THAT(m.GetBindPaths("poi"), ElementsAreArray<std::string>({"poi"}));

  EXPECT_CALL(platform_, PathExists("poi.r00")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("poi.rar"),
              ElementsAreArray<std::string>({"poi.rar"}));

  EXPECT_CALL(platform_, PathExists("poi.r00")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi.r01")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi.r02")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("poi.rar"),
              ElementsAreArray<std::string>({"poi.rar", "poi.r00", "poi.r01"}));

  EXPECT_CALL(platform_, PathExists("POI.R00")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI.R01")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI.R02")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("POI.RAR"),
              ElementsAreArray<std::string>({"POI.RAR", "POI.R00", "POI.R01"}));
}

TEST_F(RarMounterTest, GetBindPathsWithNewNamingScheme) {
  const RarMounter& m = mounter_;

  EXPECT_CALL(platform_, PathExists("poi1.rar")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("poi2.rar"),
              ElementsAreArray<std::string>({"poi2.rar"}));

  EXPECT_CALL(platform_, PathExists("poi1.rar")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi2.rar")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi3.rar")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi4.rar")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("poi5.rar")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("poi2.rar"),
              ElementsAreArray<std::string>(
                  {"poi2.rar", "poi1.rar", "poi3.rar", "poi4.rar"}));

  EXPECT_CALL(platform_, PathExists("POI1.RAR")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI2.RAR")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI3.RAR")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI4.RAR")).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("POI5.RAR")).WillOnce(Return(false));
  EXPECT_THAT(m.GetBindPaths("POI2.RAR"),
              ElementsAreArray<std::string>(
                  {"POI2.RAR", "POI1.RAR", "POI3.RAR", "POI4.RAR"}));
}

TEST_F(RarMounterTest, GetBindPathsStopsOnOverflow) {
  const RarMounter& m = mounter_;

  EXPECT_CALL(platform_, PathExists(_)).WillRepeatedly(Return(true));

  EXPECT_THAT(m.GetBindPaths("poi.rar"), SizeIs(901));
  EXPECT_THAT(m.GetBindPaths("POI.RAR"), SizeIs(901));
  EXPECT_THAT(m.GetBindPaths("poi1.rar"), SizeIs(9));
  EXPECT_THAT(m.GetBindPaths("POI1.RAR"), SizeIs(9));
  EXPECT_THAT(m.GetBindPaths("poi01.rar"), SizeIs(99));
  EXPECT_THAT(m.GetBindPaths("POI01.RAR"), SizeIs(99));
  EXPECT_THAT(m.GetBindPaths("poi001.rar"), SizeIs(999));
  EXPECT_THAT(m.GetBindPaths("POI001.RAR"), SizeIs(999));
}

}  // namespace cros_disks
