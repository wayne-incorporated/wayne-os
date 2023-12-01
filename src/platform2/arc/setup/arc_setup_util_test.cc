// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// How to build and run the tests:
//
// chroot$ cros_run_unit_tests --board=$BOARD --packages arc-setup
//
// Note: only x86 $BOARDs like cyan are supported.

#include "arc/setup/arc_setup_util.h"

#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <limits>
#include <optional>
#include <set>
#include <utility>

#include <base/base64.h>
#include <base/environment.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/rand_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/file_utils.h>
#include <brillo/files/safe_fd.h>
#include <gtest/gtest.h>
#include <libsegmentation/feature_management.h>
#include <libsegmentation/feature_management_fake.h>

namespace arc {

namespace {

constexpr char kTestProperitesFromFileContent[] =
    ""
    "# begin build properties\n"
    "\n"
    "ro.build.version.sdk=25\n"
    "ro.product.board=board\n"
    "ro.build.fingerprint=fingerprint\n";

constexpr char kTestProperitesFromFileContentBad[] =
    ""
    "# begin build properties\n"
    "\n"
    "ro.build.version.sdk=25\n"
    "ro.product.board board\n";  // no '=' separator

struct FilterMediaProfileParam {
  std::optional<std::string> test_config_content;
  std::string media_profile_content;
  std::string result_content;
};

std::string TestFrontCameraProfile(int cameraId) {
  std::string cameraIdStr = cameraId == 0 ? "0" : "1";
  return R"(    <CamcorderProfiles cameraId=")" + cameraIdStr + R"(">
        <EncoderProfile quality="720p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="8000000"
                   width="1280"
                   height="720"
                   frameRate="30" />
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <EncoderProfile quality="timelapse720p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="8000000"
                   width="1280"
                   height="720"
                   frameRate="30" />
            <!-- Audio settings are not used for timealpse video recording -->
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <ImageEncoding quality="90" />
        <ImageEncoding quality="80" />
        <ImageEncoding quality="70" />
        <ImageDecoding memCap="20000000" />
    </CamcorderProfiles>
)";
}

std::string TestBackCameraProfile(int cameraId) {
  std::string cameraIdStr = cameraId == 0 ? "0" : "1";
  return R"(    <CamcorderProfiles cameraId=")" + cameraIdStr + R"(">
        <EncoderProfile quality="720p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="8000000"
                   width="1280"
                   height="720"
                   frameRate="30" />
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <EncoderProfile quality="timelapse720p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="8000000"
                   width="1280"
                   height="720"
                   frameRate="30" />
            <!-- Audio settings are not used for timealpse video recording -->
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <EncoderProfile quality="1080p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="17000000"
                   width="1920"
                   height="1080"
                   frameRate="30" />
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <EncoderProfile quality="timelapse1080p" fileFormat="mp4" duration="60">
            <Video codec="h264"
                   bitRate="17000000"
                   width="1920"
                   height="1080"
                   frameRate="30" />
            <!-- Audio settings are not used for timealpse video recording -->
            <Audio codec="aac"
                   bitRate="96000"
                   sampleRate="44100"
                   channels="1" />
        </EncoderProfile>
        <ImageEncoding quality="90" />
        <ImageEncoding quality="80" />
        <ImageEncoding quality="70" />
        <ImageDecoding memCap="20000000" />
    </CamcorderProfiles>
)";
}

std::string TestMediaProfile(bool has_front_camera, bool has_back_camera) {
  return R"(<?xml version="1.0" encoding="utf-8"?>
<!-- Copyright 2017 The Android Open Source Project

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.
-->
<!DOCTYPE MediaSettings [
<!ELEMENT MediaSettings (CamcorderProfiles,
                         EncoderOutputFileFormat+,
                         VideoEncoderCap+,
                         AudioEncoderCap+,
                         VideoDecoderCap,
                         AudioDecoderCap)>
<!ELEMENT CamcorderProfiles (EncoderProfile+, ImageEncoding+, ImageDecoding,
Camera)>
<!ELEMENT EncoderProfile (Video, Audio)>
<!ATTLIST EncoderProfile quality (high|low) #REQUIRED>
<!ATTLIST EncoderProfile fileFormat (mp4|3gp) #REQUIRED>
<!ATTLIST EncoderProfile duration (30|60) #REQUIRED>
<!ELEMENT Video EMPTY>
<!ATTLIST Video codec (h264|h263|m4v) #REQUIRED>
<!ATTLIST Video bitRate CDATA #REQUIRED>
<!ATTLIST Video width CDATA #REQUIRED>
<!ATTLIST Video height CDATA #REQUIRED>
<!ATTLIST Video frameRate CDATA #REQUIRED>
<!ELEMENT Audio EMPTY>
<!ATTLIST Audio codec (amrnb|amrwb|aac) #REQUIRED>
<!ATTLIST Audio bitRate CDATA #REQUIRED>
<!ATTLIST Audio sampleRate CDATA #REQUIRED>
<!ATTLIST Audio channels (1|2) #REQUIRED>
<!ELEMENT ImageEncoding EMPTY>
<!ATTLIST ImageEncoding quality (90|80|70|60|50|40) #REQUIRED>
<!ELEMENT ImageDecoding EMPTY>
<!ATTLIST ImageDecoding memCap CDATA #REQUIRED>
<!ELEMENT Camera EMPTY>
<!ELEMENT EncoderOutputFileFormat EMPTY>
<!ATTLIST EncoderOutputFileFormat name (mp4|3gp) #REQUIRED>
<!ELEMENT VideoEncoderCap EMPTY>
<!ATTLIST VideoEncoderCap name (h264|h263|m4v|wmv) #REQUIRED>
<!ATTLIST VideoEncoderCap enabled (true|false) #REQUIRED>
<!ATTLIST VideoEncoderCap minBitRate CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap maxBitRate CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap minFrameWidth CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap maxFrameWidth CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap minFrameHeight CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap maxFrameHeight CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap minFrameRate CDATA #REQUIRED>
<!ATTLIST VideoEncoderCap maxFrameRate CDATA #REQUIRED>
<!ELEMENT AudioEncoderCap EMPTY>
<!ATTLIST AudioEncoderCap name (amrnb|amrwb|aac|wma) #REQUIRED>
<!ATTLIST AudioEncoderCap enabled (true|false) #REQUIRED>
<!ATTLIST AudioEncoderCap minBitRate CDATA #REQUIRED>
<!ATTLIST AudioEncoderCap maxBitRate CDATA #REQUIRED>
<!ATTLIST AudioEncoderCap minSampleRate CDATA #REQUIRED>
<!ATTLIST AudioEncoderCap maxSampleRate CDATA #REQUIRED>
<!ATTLIST AudioEncoderCap minChannels (1|2) #REQUIRED>
<!ATTLIST AudioEncoderCap maxChannels (1|2) #REQUIRED>
<!ELEMENT VideoDecoderCap EMPTY>
<!ATTLIST VideoDecoderCap name (wmv) #REQUIRED>
<!ATTLIST VideoDecoderCap enabled (true|false) #REQUIRED>
<!ELEMENT AudioDecoderCap EMPTY>
<!ATTLIST AudioDecoderCap name (wma) #REQUIRED>
<!ATTLIST AudioDecoderCap enabled (true|false) #REQUIRED>
]>
<!--
     This file is used to declare the multimedia profiles and capabilities
     on an android-powered device.
-->
<MediaSettings>
)" + (has_back_camera ? TestBackCameraProfile(0) : "") +
         (has_front_camera ? TestFrontCameraProfile(has_back_camera ? 1 : 0)
                           : "") +
         R"(
    <EncoderOutputFileFormat name="3gp" />
    <EncoderOutputFileFormat name="mp4" />

    <!--
         If a codec is not enabled, it is invisible to the applications
         In other words, the applications won't be able to use the codec
         or query the capabilities of the codec at all if it is disabled
    -->
    <VideoEncoderCap name="h264" enabled="true"
        minBitRate="64000" maxBitRate="17000000"
        minFrameWidth="320" maxFrameWidth="1920"
        minFrameHeight="240" maxFrameHeight="1080"
        minFrameRate="15" maxFrameRate="30" />

    <VideoEncoderCap name="h263" enabled="true"
        minBitRate="64000" maxBitRate="1000000"
        minFrameWidth="320" maxFrameWidth="1920"
        minFrameHeight="240" maxFrameHeight="1080"
        minFrameRate="15" maxFrameRate="30" />

    <VideoEncoderCap name="m4v" enabled="true"
        minBitRate="64000" maxBitRate="2000000"
        minFrameWidth="320" maxFrameWidth="1920"
        minFrameHeight="240" maxFrameHeight="1080"
        minFrameRate="15" maxFrameRate="30" />

    <AudioEncoderCap name="aac" enabled="true"
        minBitRate="758" maxBitRate="288000"
        minSampleRate="8000" maxSampleRate="48000"
        minChannels="1" maxChannels="1" />

    <AudioEncoderCap name="heaac" enabled="true"
        minBitRate="8000" maxBitRate="64000"
        minSampleRate="16000" maxSampleRate="48000"
        minChannels="1" maxChannels="1" />

    <AudioEncoderCap name="aaceld" enabled="true"
        minBitRate="16000" maxBitRate="192000"
        minSampleRate="16000" maxSampleRate="48000"
        minChannels="1" maxChannels="1" />

    <AudioEncoderCap name="amrwb" enabled="true"
        minBitRate="6600" maxBitRate="23050"
        minSampleRate="16000" maxSampleRate="16000"
        minChannels="1" maxChannels="1" />

    <AudioEncoderCap name="amrnb" enabled="true"
        minBitRate="5525" maxBitRate="12200"
        minSampleRate="8000" maxSampleRate="8000"
        minChannels="1" maxChannels="1" />

    <!--
        FIXME:
        We do not check decoder capabilities at present
        At present, we only check whether windows media is visible
        for TEST applications. For other applications, we do
        not perform any checks at all.
    -->
    <VideoDecoderCap name="wmv" enabled="false"/>
    <AudioDecoderCap name="wma" enabled="false"/>
</MediaSettings>
)";
}

class FilterMediaProfileTest
    : public ::testing::TestWithParam<FilterMediaProfileParam> {};

const FilterMediaProfileParam kFilterMediaProfileParam[] = {
    {std::nullopt,
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true),
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true)},
    {R"({"enable_front_camera": true, "enable_back_camera": true})",
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true),
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true)},
    {R"({"enable_front_camera": false, "enable_back_camera": true})",
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true),
     TestMediaProfile(/* has_front_camera */ false,
                      /* has_back_camera */ true)},
    {R"({"enable_front_camera": true, "enable_back_camera": false})",
     TestMediaProfile(/* has_front_camera */ true, /* has_back_camera */ true),
     TestMediaProfile(/* has_front_camera */ true,
                      /* has_back_camera */ false)},
};

struct AppendFeatureManagementParam {
  std::set<std::string> test_features;
  std::string hardware_property_content;
  std::string result_content;
};

const char BasicHardwareFeatureContent[] =
    R"(<?xml version="1.0" encoding="utf-8"?>
<permissions>
  <unavailable-feature name="android.hardware.camera"/>
  <unavailable-feature name="android.hardware.camera.capability.manual_sensor"/>
  <feature name="android.hardware.sensor.light"/>
</permissions>
)";

const char OneFeatureHardwareFeatureContent[] =
    R"(<?xml version="1.0" encoding="utf-8"?>
<permissions>
  <unavailable-feature name="android.hardware.camera"/>
  <unavailable-feature name="android.hardware.camera.capability.manual_sensor"/>
  <feature name="android.hardware.sensor.light"/>
  <feature name="org.chromium.arc.feature_management.Feat1"/>
</permissions>
)";

const char TwoFeatureHardwareFeatureContent[] =
    R"(<?xml version="1.0" encoding="utf-8"?>
<permissions>
  <unavailable-feature name="android.hardware.camera"/>
  <unavailable-feature name="android.hardware.camera.capability.manual_sensor"/>
  <feature name="android.hardware.sensor.light"/>
  <feature name="org.chromium.arc.feature_management.Feat1"/>
  <feature name="org.chromium.arc.feature_management.Feat2"/>
</permissions>
)";

class AppendFeatureManagementTest
    : public ::testing::TestWithParam<AppendFeatureManagementParam> {};

const AppendFeatureManagementParam kAppendFeatureManagementParam[] = {
    {{}, BasicHardwareFeatureContent, BasicHardwareFeatureContent},
    {{"Feat1"}, BasicHardwareFeatureContent, OneFeatureHardwareFeatureContent},
    {{"Feat1", "Feat2"},
     BasicHardwareFeatureContent,
     TwoFeatureHardwareFeatureContent},
};

}  // namespace

TEST(ArcSetupUtil, TestCreateOrTruncate) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  // Create a new empty file.
  EXPECT_TRUE(CreateOrTruncate(temp_directory.GetPath().Append("file"), 0777));
  // Confirm that the mode of the file is 0777.
  int mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("file"), &mode));
  EXPECT_EQ(0777, mode);
  // Confirm that the size of the file is 0.
  int64_t size = -1;
  EXPECT_TRUE(
      base::GetFileSize(temp_directory.GetPath().Append("file"), &size));
  EXPECT_EQ(0, size);

  // Make the file non-empty.
  EXPECT_TRUE(
      WriteToFile(temp_directory.GetPath().Append("file"), 0777, "abc"));
  EXPECT_TRUE(
      base::GetFileSize(temp_directory.GetPath().Append("file"), &size));
  EXPECT_EQ(3, size);

  // Call the API again with a different mode.
  EXPECT_TRUE(CreateOrTruncate(temp_directory.GetPath().Append("file"), 0700));
  // Confirm that the mode of the file is now 0700.
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("file"), &mode));
  EXPECT_EQ(0700, mode);
  // Confirm that the size of the file is still 0.
  size = -1;
  EXPECT_TRUE(
      base::GetFileSize(temp_directory.GetPath().Append("file"), &size));
  EXPECT_EQ(0, size);
}

TEST(ArcSetupUtil, TestWaitForPaths) {
  constexpr base::TimeDelta timeout = base::Seconds(1);

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::ScopedTempDir temp_dir2;
  ASSERT_TRUE(temp_dir2.CreateUniqueTempDir());

  // Confirm that when the first argument is empty, it returns true.
  // Also confirm that the third argument can be nullptr.
  EXPECT_TRUE(WaitForPaths({}, timeout, nullptr));

  // Confirm that the function can handle one path.
  base::TimeDelta elapsed;
  EXPECT_TRUE(WaitForPaths({temp_dir.GetPath()}, timeout, &elapsed));
  EXPECT_GT(elapsed, base::TimeDelta());
  // Strictly speaking, WaitForPaths does not guarantee this, but in practice,
  // this check passes.
  EXPECT_LE(elapsed, timeout);
  elapsed = base::TimeDelta();

  // Does the same with a nonexistent file.
  EXPECT_FALSE(WaitForPaths({temp_dir.GetPath().Append("nonexistent")}, timeout,
                            &elapsed));
  EXPECT_GT(elapsed, timeout);
  elapsed = base::TimeDelta();

  // Confirm that the function can handle two paths.
  EXPECT_TRUE(WaitForPaths({temp_dir.GetPath(), temp_dir2.GetPath()}, timeout,
                           &elapsed));
  EXPECT_GT(elapsed, base::TimeDelta());
  EXPECT_LE(elapsed, timeout);  // same
  elapsed = base::TimeDelta();

  EXPECT_FALSE(WaitForPaths(
      {temp_dir.GetPath().Append("nonexistent"), temp_dir2.GetPath()}, timeout,
      &elapsed));
  EXPECT_GT(elapsed, timeout);
  elapsed = base::TimeDelta();

  EXPECT_FALSE(WaitForPaths(
      {temp_dir.GetPath(), temp_dir2.GetPath().Append("nonexistent")}, timeout,
      &elapsed));
  EXPECT_GT(elapsed, timeout);
  elapsed = base::TimeDelta();

  EXPECT_FALSE(WaitForPaths({temp_dir.GetPath().Append("nonexistent"),
                             temp_dir2.GetPath().Append("nonexistent")},
                            timeout, &elapsed));
  EXPECT_GT(elapsed, timeout);
}

TEST(ArcSetupUtil, TestWriteToFile) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  // Create a non-empty file.
  EXPECT_TRUE(
      WriteToFile(temp_directory.GetPath().Append("file"), 0700, "abcde"));
  // Confirm that the mode of the file is now 0700.
  int mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("file"), &mode));
  EXPECT_EQ(0700, mode);
  // Confirm that the size of the file is still 0.
  int64_t size = -1;
  EXPECT_TRUE(
      base::GetFileSize(temp_directory.GetPath().Append("file"), &size));
  EXPECT_EQ(5, size);

  // Call the API again with a different mode and content.
  EXPECT_TRUE(
      WriteToFile(temp_directory.GetPath().Append("file"), 0777, "xyz"));
  // Confirm that the mode of the file is now 0700.
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("file"), &mode));
  EXPECT_EQ(0777, mode);
  // Confirm that the size of the file is still 0.
  size = -1;
  EXPECT_TRUE(
      base::GetFileSize(temp_directory.GetPath().Append("file"), &size));
  EXPECT_EQ(3, size);
}

TEST(ArcSetupUtil, TestWriteToFileWithSymlink) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::ScopedTempDir temp_directory2;
  ASSERT_TRUE(temp_directory2.CreateUniqueTempDir());

  const base::FilePath symlink = temp_directory.GetPath().Append("symlink");
  ASSERT_TRUE(base::CreateSymbolicLink(temp_directory2.GetPath(), symlink));

  // WriteToFile should fail when the path points to a symlink.
  EXPECT_FALSE(WriteToFile(symlink, 0777, "abc"));

  // WriteToFile should also fail when a path component in the middle is a
  // symlink.
  const base::FilePath path_with_symlink = symlink.Append("not-a-symlink");
  EXPECT_FALSE(WriteToFile(path_with_symlink, 0777, "abcde"));
}

TEST(ArcSetupUtil, TestWriteToFileWithFifo) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath fifo = temp_directory.GetPath().Append("fifo");
  ASSERT_EQ(0, mkfifo(fifo.value().c_str(), 0700));

  // WriteToFile should fail when the path points to a fifo.
  EXPECT_FALSE(WriteToFile(fifo, 0777, "abc"));
}

TEST(ArcSetupUtil, TestGetPropertyFromFile) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath prop_file = temp_directory.GetPath().Append("test.prop");

  // Create a new prop file and read it.
  ASSERT_TRUE(WriteToFile(prop_file, 0700, "key=val"));
  std::string v;
  EXPECT_TRUE(GetPropertyFromFile(prop_file, "key", &v));
  EXPECT_EQ("val", v);
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "k", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "ke", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "keyX", &v));

  // Retry with an empty file.
  ASSERT_TRUE(WriteToFile(prop_file, 0700, ""));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "key", &v));

  // Retry with a multi-line file.
  ASSERT_TRUE(WriteToFile(prop_file, 0700, "k1=v1\nk2=v2\nk3=v3"));
  EXPECT_TRUE(GetPropertyFromFile(prop_file, "k1", &v));
  EXPECT_EQ("v1", v);
  EXPECT_TRUE(GetPropertyFromFile(prop_file, "k2", &v));
  EXPECT_EQ("v2", v);
  EXPECT_TRUE(GetPropertyFromFile(prop_file, "k3", &v));
  EXPECT_EQ("v3", v);
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "=", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "1", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "k", &v));
  EXPECT_FALSE(GetPropertyFromFile(prop_file, "k4", &v));
}

TEST(ArcSetupUtil, TestGetPropertiesFromFile) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath prop_file = temp_directory.GetPath().Append("test.prop");

  // Create a new prop file and read it.
  ASSERT_TRUE(WriteToFile(prop_file, 0700, kTestProperitesFromFileContent));
  std::map<std::string, std::string> properties;
  EXPECT_TRUE(GetPropertiesFromFile(prop_file, &properties));
  EXPECT_EQ(3U, properties.size());
  EXPECT_EQ("25", properties["ro.build.version.sdk"]);
  EXPECT_EQ("board", properties["ro.product.board"]);
  EXPECT_EQ("fingerprint", properties["ro.build.fingerprint"]);
}

TEST(ArcSetupUtil, TestGetPropertiesFromFileBad) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath prop_file = temp_directory.GetPath().Append("test.prop");

  // Create a new prop file and read it.
  ASSERT_TRUE(WriteToFile(prop_file, 0700, kTestProperitesFromFileContentBad));
  std::map<std::string, std::string> properties;
  EXPECT_FALSE(GetPropertiesFromFile(prop_file, &properties));
  EXPECT_TRUE(properties.empty());
}

TEST(ArcSetupUtil, TestInstallDirectory) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  // Set |temp_directory| to 0707.
  EXPECT_TRUE(base::SetPosixFilePermissions(temp_directory.GetPath(), 0707));

  // Create a new directory.
  EXPECT_TRUE(InstallDirectory(0777, getuid(), getgid(),
                               temp_directory.GetPath().Append("sub1/sub2")));
  // Confirm that the mode for sub2 is 0777.
  int mode_sub2 = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("sub1/sub2"), &mode_sub2));
  EXPECT_EQ(0777, mode_sub2);
  // Confirm that the mode for sub1 is NOT 0777 but the secure default, 0755.
  int mode_sub1 = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("sub1"), &mode_sub1));
  EXPECT_EQ(0755, mode_sub1);

  // Confirm that the existing directory |temp_directory| still has 0707 mode.
  int mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(temp_directory.GetPath(), &mode));
  EXPECT_EQ(0707, mode);

  // Call InstallDirectory again with the same path but a different mode, 01700.
  EXPECT_TRUE(InstallDirectory(0700 | S_ISVTX, getuid(), getgid(),
                               temp_directory.GetPath().Append("sub1/sub2")));
  // Confirm that the mode for sub2 is now 01700.
  struct stat st;
  EXPECT_EQ(
      0,
      stat(temp_directory.GetPath().Append("sub1/sub2").value().c_str(), &st));
  EXPECT_EQ(0700 | S_ISVTX, st.st_mode & ~S_IFMT);
  mode_sub2 = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("sub1/sub2"), &mode_sub2));
  EXPECT_EQ(0700, mode_sub2);  // base's function masks the mode with 0777.
  // Confirm that the mode for sub1 is still 0755.
  mode_sub1 = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_directory.GetPath().Append("sub1"), &mode_sub1));
  EXPECT_EQ(0755, mode_sub1);
  // Confirm that the existing directory |temp_directory| still has 0707 mode.
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(temp_directory.GetPath(), &mode));
  EXPECT_EQ(0707, mode);
}

TEST(ArcSetupUtil, TestInstallDirectoryWithSymlink) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::ScopedTempDir temp_directory2;
  ASSERT_TRUE(temp_directory2.CreateUniqueTempDir());

  const base::FilePath symlink = temp_directory.GetPath().Append("symlink");
  ASSERT_TRUE(base::CreateSymbolicLink(temp_directory2.GetPath(), symlink));

  // InstallDirectory should fail when the path points to a symlink.
  EXPECT_FALSE(InstallDirectory(0777, getuid(), getgid(), symlink));

  // InstallDirectory should also fail when a path component in the middle
  // is a symlink.
  const base::FilePath path_with_symlink = symlink.Append("not-a-symlink");
  EXPECT_FALSE(InstallDirectory(0777, getuid(), getgid(), path_with_symlink));
}

TEST(ArcSetupUtil, TestInstallDirectoryWithFifo) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath fifo = temp_directory.GetPath().Append("fifo");
  ASSERT_EQ(0, mkfifo(fifo.value().c_str(), 0700));

  // InstallDirectory should fail when the path points to a fifo.
  EXPECT_FALSE(InstallDirectory(0777, getuid(), getgid(), fifo));
}

TEST(ArcSetupUtil, TestDeleteFilesInDir) {
  base::ScopedTempDir directory;
  ASSERT_TRUE(directory.CreateUniqueTempDir());
  ASSERT_TRUE(brillo::MkdirRecursively(directory.GetPath().Append("arm"), 0755)
                  .is_valid());
  ASSERT_TRUE(
      brillo::MkdirRecursively(directory.GetPath().Append("arm64"), 0755)
          .is_valid());
  ASSERT_TRUE(CreateOrTruncate(
      directory.GetPath().Append("arm/system@framework@boot.art"), 0755));
  ASSERT_TRUE(CreateOrTruncate(
      directory.GetPath().Append("arm64/system@framework@boot.art"), 0755));
  EXPECT_TRUE(base::PathExists(
      directory.GetPath().Append("arm/system@framework@boot.art")));
  EXPECT_TRUE(base::PathExists(
      directory.GetPath().Append("arm/system@framework@boot.art")));

  EXPECT_TRUE(arc::DeleteFilesInDir(directory.GetPath()));

  EXPECT_TRUE(base::PathExists(directory.GetPath().Append("arm")));
  EXPECT_TRUE(base::PathExists(directory.GetPath().Append("arm64")));
  EXPECT_FALSE(base::PathExists(
      directory.GetPath().Append("arm/system@framework@boot.art")));
  EXPECT_FALSE(base::PathExists(
      directory.GetPath().Append("arm/system@framework@boot.art")));
}

TEST(ArcSetupUtil, TestLaunchAndWait) {
  base::ElapsedTimer timer;
  // Check that LaunchAndWait actually blocks until sleep returns.
  EXPECT_TRUE(LaunchAndWait({"/usr/bin/sleep", "1"}));
  EXPECT_LE(1, timer.Elapsed().InSeconds());

  EXPECT_FALSE(LaunchAndWait({"/bin/false"}));
  EXPECT_FALSE(LaunchAndWait({"/no_such_binary"}));
}

TEST(ArcSetupUtil, TestGenerateFakeSerialNumber) {
  // Check that the function always returns 20-character string.
  EXPECT_EQ(20U,
            GenerateFakeSerialNumber("mytestaccount@gmail.com", "001122aabbcc")
                .size());
  EXPECT_EQ(20U, GenerateFakeSerialNumber("", "").size());
  EXPECT_EQ(20U, GenerateFakeSerialNumber("a", "b").size());

  // Check that the function always returns the same ID for the same
  // account and hwid_raw.
  const std::string id_1 =
      GenerateFakeSerialNumber("mytestaccount@gmail.com", "001122aabbcc");
  const std::string id_2 =
      GenerateFakeSerialNumber("mytestaccount@gmail.com", "001122aabbcc");
  EXPECT_EQ(id_1, id_2);

  // Generate an ID for a different account but for the same machine.
  // Check that the ID is not the same as |id_1|.
  const std::string id_3 =
      GenerateFakeSerialNumber("mytestaccount2@gmail.com", "001122aabbcc");
  EXPECT_NE(id_1, id_3);

  // Generate an ID for a different machine but for the same account.
  // Check that the ID is not the same as |id_1|.
  const std::string id_4 =
      GenerateFakeSerialNumber("mytestaccount@gmail.com", "001122aaddcc");
  EXPECT_NE(id_1, id_4);

  // Check that the function treats '\0' in |salt| properly.
  const std::string id_5 =
      GenerateFakeSerialNumber("mytestaccount@gmail.com", {'a', '\0', 'b'});
  const std::string id_6 =
      GenerateFakeSerialNumber("mytestaccount@gmail.com", {'a', '\0', 'c'});
  EXPECT_NE(id_5, id_6);
}

TEST(ArcSetupUtil, TestGetArtCompilationOffsetSeed) {
  const uint64_t seed1 = GetArtCompilationOffsetSeed("salt1", "build1");
  const uint64_t seed2 = GetArtCompilationOffsetSeed("salt2", "build1");
  const uint64_t seed3 = GetArtCompilationOffsetSeed("salt1", "build2");
  EXPECT_NE(0ULL, seed1);
  EXPECT_NE(0ULL, seed2);
  EXPECT_NE(0ULL, seed3);
  EXPECT_NE(seed1, seed2);
  EXPECT_NE(seed2, seed3);
  EXPECT_NE(seed3, seed1);
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());
  base::FilePath dir = test_dir.GetPath().Append("android-data");
  base::FilePath data_old_dir = test_dir.GetPath().Append("android-data-old");

  // Create android-data/path/to/file and run MoveDirIntoDataOldDir.
  ASSERT_TRUE(brillo::MkdirRecursively(
                  test_dir.GetPath().Append("android-data/path/to"), 0755)
                  .is_valid());
  ASSERT_TRUE(CreateOrTruncate(
      test_dir.GetPath().Append("android-data/path/to/file"), 0755));
  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));
  EXPECT_TRUE(base::IsDirectoryEmpty(dir));

  // android-data has been cleared.
  // Create android-data/path/to/file and run MoveDirIntoDataOldDir again.
  ASSERT_TRUE(brillo::MkdirRecursively(
                  test_dir.GetPath().Append("android-data/path/to"), 0755)
                  .is_valid());
  ASSERT_TRUE(CreateOrTruncate(
      test_dir.GetPath().Append("android-data/path/to/file"), 0755));
  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_TRUE(base::IsDirectoryEmpty(dir));
  ASSERT_TRUE(base::DirectoryExists(data_old_dir));

  // There should be two temp dirs in android-data-old now.
  // Both temp dirs should contain path/to/file.
  base::FileEnumerator temp_dir_iter(data_old_dir, false,
                                     base::FileEnumerator::DIRECTORIES);
  base::FilePath temp_dir;
  int temp_dir_count = 0;
  while (!(temp_dir = temp_dir_iter.Next()).empty()) {
    EXPECT_TRUE(base::PathExists(temp_dir.Append("path/to/file")));
    ++temp_dir_count;
  }
  EXPECT_EQ(2, temp_dir_count);
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_AndroidDataDirDoesNotExist) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  base::FilePath dir = test_dir.GetPath().Append("android-data");
  base::FilePath data_old_dir = test_dir.GetPath().Append("android-data-old");

  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_TRUE(base::IsDirectoryEmpty(dir));
  EXPECT_TRUE(base::IsDirectoryEmpty(data_old_dir));
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_AndroidDataDirIsEmpty) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  base::FilePath dir = test_dir.GetPath().Append("android-data");
  base::FilePath data_old_dir = test_dir.GetPath().Append("android-data-old");

  ASSERT_TRUE(
      brillo::MkdirRecursively(test_dir.GetPath().Append("android-data"), 0755)
          .is_valid());

  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_FALSE(base::DirectoryExists(dir));

  base::FileEnumerator temp_dir_iter(data_old_dir, false /* recursive */,
                                     base::FileEnumerator::DIRECTORIES);
  base::FilePath temp_dir;
  int temp_dir_count = 0;
  while (!(temp_dir = temp_dir_iter.Next()).empty()) {
    EXPECT_TRUE(base::IsDirectoryEmpty(temp_dir));
    ++temp_dir_count;
  }
  EXPECT_EQ(1, temp_dir_count);
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_AndroidDataDirIsFile) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  base::FilePath dir = test_dir.GetPath().Append("android-data");
  base::FilePath data_old_dir = test_dir.GetPath().Append("android-data-old");

  // dir is a file, not a directory.
  ASSERT_TRUE(CreateOrTruncate(dir, 0755));

  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_TRUE(base::PathExists(dir));
  EXPECT_TRUE(base::IsDirectoryEmpty(data_old_dir));
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_AndroidDataOldIsFile) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  base::FilePath dir = test_dir.GetPath().Append("android-data");
  base::FilePath data_old_dir = test_dir.GetPath().Append("android-data-old");

  ASSERT_TRUE(brillo::MkdirRecursively(
                  test_dir.GetPath().Append("android-data/path/to"), 0755)
                  .is_valid());
  ASSERT_TRUE(CreateOrTruncate(
      test_dir.GetPath().Append("android-data/path/to/file"), 0755));

  // Create a file (not a directory) named android-data-old.
  ASSERT_TRUE(
      CreateOrTruncate(test_dir.GetPath().Append("android-data-old"), 0755));

  // This should remove the file named android-data-old and create
  // android-data-old dir instead.
  EXPECT_TRUE(MoveDirIntoDataOldDir(dir, data_old_dir));

  base::FileEnumerator temp_dir_iter(data_old_dir, false,
                                     base::FileEnumerator::DIRECTORIES);
  base::FilePath temp_dir;
  int temp_dir_count = 0;
  while (!(temp_dir = temp_dir_iter.Next()).empty()) {
    EXPECT_TRUE(base::PathExists(temp_dir.Append("path/to/file")));
    ++temp_dir_count;
  }
  EXPECT_EQ(1, temp_dir_count);
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_DirUnderSymlink) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  const base::FilePath target = test_dir.GetPath().Append("symlink_target");
  const base::FilePath test_file = target.Append("android-data/path/to/file");
  ASSERT_TRUE(brillo::MkdirRecursively(test_file.DirName(), 0755).is_valid());
  ASSERT_TRUE(CreateOrTruncate(test_file, 0755));

  base::FilePath data_old_dir =
      test_dir.GetPath().Append("old-parent/android-data-old");
  ASSERT_TRUE(brillo::MkdirRecursively(data_old_dir, 0755).is_valid());

  base::FilePath dir = test_dir.GetPath().Append("data-parent/android-data");
  ASSERT_TRUE(base::CreateSymbolicLink(target, dir.DirName()));

  EXPECT_FALSE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_TRUE(base::IsDirectoryEmpty(data_old_dir));
  EXPECT_TRUE(base::PathExists(test_file));
}

TEST(ArcSetupUtil, MoveDirIntoDataOldDir_OldDirUnderSymlink) {
  base::ScopedTempDir test_dir;
  ASSERT_TRUE(test_dir.CreateUniqueTempDir());

  base::FilePath dir = test_dir.GetPath().Append("data-parent/android-data");
  base::FilePath data_old_dir =
      test_dir.GetPath().Append("old-parent/android-data-old");

  const base::FilePath target = test_dir.GetPath().Append("symlink_target");
  ASSERT_TRUE(brillo::MkdirRecursively(target.Append("android-data-old"), 0755)
                  .is_valid());

  ASSERT_TRUE(base::CreateSymbolicLink(target, data_old_dir.DirName()));

  const base::FilePath test_file = dir.Append("path/to/file");
  ASSERT_TRUE(brillo::MkdirRecursively(test_file.DirName(), 0755).is_valid());
  ASSERT_TRUE(CreateOrTruncate(test_file, 0755));

  EXPECT_FALSE(MoveDirIntoDataOldDir(dir, data_old_dir));

  EXPECT_TRUE(base::PathExists(dir));
  EXPECT_TRUE(base::IsDirectoryEmpty(target.Append("android-data-old")));
}

TEST(ArcSetupUtil, TestGetChromeOsChannelFromFile) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath prop_file = temp_directory.GetPath().Append("test.prop");

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=beta-channel"));
  EXPECT_EQ("beta", GetChromeOsChannelFromFile(prop_file));

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=canary-channel"));
  EXPECT_EQ("canary", GetChromeOsChannelFromFile(prop_file));

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=dev-channel"));
  EXPECT_EQ("dev", GetChromeOsChannelFromFile(prop_file));

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=dogfood-channel"));
  EXPECT_EQ("dogfood", GetChromeOsChannelFromFile(prop_file));

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=stable-channel"));
  EXPECT_EQ("stable", GetChromeOsChannelFromFile(prop_file));

  ASSERT_TRUE(
      WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=testimage-channel"));
  EXPECT_EQ("testimage", GetChromeOsChannelFromFile(prop_file));

  // Checked "unknown" is returned if no value is set
  ASSERT_TRUE(WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK="));
  EXPECT_EQ("unknown", GetChromeOsChannelFromFile(prop_file));

  // Checked "unknown" is returned if some unknown string is set
  ASSERT_TRUE(WriteToFile(prop_file, 0700, "CHROMEOS_RELEASE_TRACK=foo_bar"));
  EXPECT_EQ("unknown", GetChromeOsChannelFromFile(prop_file));

  // Checked "unknown" is returned if CHROMEOS_RELEASE_TRACK is not in the file
  ASSERT_TRUE(WriteToFile(prop_file, 0700, " "));
  EXPECT_EQ("unknown", GetChromeOsChannelFromFile(prop_file));

  // Checked "unknown" is returned if file is not present
  EXPECT_EQ("unknown", GetChromeOsChannelFromFile(base::FilePath("foo")));
}

TEST(ArcSetupUtil, TestParseContainerState) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath json_file = temp_directory.GetPath().Append("state.json");

  const base::FilePath kRootfsPath(
      "/opt/google/containers/android/rootfs/root");

  constexpr char kJsonTemplate[] = R"json(
    {
      "ociVersion": "1.0",
      "id": "android-container",
      "status": "created",
      "pid": 4422,
      "bundle": "/opt/google/containers/android",
      "annotations": {
        "org.chromium.run_oci.container_root": "%s"
      }
    }
  )json";

  ASSERT_TRUE(WriteToFile(
      json_file, 0700,
      base::StringPrintf(kJsonTemplate,
                         temp_directory.GetPath().value().c_str())));
  ASSERT_TRUE(brillo::MkdirRecursively(
                  temp_directory.GetPath().Append("mountpoints"), 0755)
                  .is_valid());
  ASSERT_TRUE(base::CreateSymbolicLink(
      kRootfsPath,
      temp_directory.GetPath().Append("mountpoints/container-root")));

  pid_t container_pid;
  base::FilePath rootfs;
  EXPECT_TRUE(GetOciContainerState(json_file, &container_pid, &rootfs));
  EXPECT_EQ(4422, container_pid);
  EXPECT_EQ(kRootfsPath, rootfs);
}

TEST(ArcSetupUtil, TestIsProcessAlive) {
  EXPECT_TRUE(IsProcessAlive(getpid()));
  // We can reasonably expect that a process with a large enough pid doesn't
  // exist.
  EXPECT_FALSE(IsProcessAlive(std::numeric_limits<pid_t>::max()));
}

TEST(ArcSetupUtil, TestGetSha1HashOfFiles) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  const base::FilePath file1 = temp_directory.GetPath().Append("file1");
  const base::FilePath file2 = temp_directory.GetPath().Append("file2");

  // Create the files.
  EXPECT_TRUE(WriteToFile(file1, 0700, "The quick brown fox "));
  EXPECT_TRUE(WriteToFile(file2, 0700, "jumps over the lazy dog"));

  // Get the hash of these files.
  std::string hash;
  EXPECT_TRUE(GetSha1HashOfFiles({file1, file2}, &hash));

  // Compare it with the pre-computed value. The value can be obtained with:
  //   $ echo -n "The quick brown fox jumps over the lazy dog" |
  //       openssl sha1 -binary | base64
  std::string hash_expected;
  EXPECT_TRUE(
      base::Base64Decode("L9ThxnotKPzthJ7hu3bnORuT6xI=", &hash_expected));
  EXPECT_EQ(hash_expected, hash);

  // Check that the function can accept an empty input.
  EXPECT_TRUE(GetSha1HashOfFiles({}, &hash));
  EXPECT_TRUE(
      base::Base64Decode("2jmj7l5rSw0yVb/vlWAYkK/YBwk=", &hash_expected));
  EXPECT_EQ(hash_expected, hash);

  // Check that the function returns false when one of the input files does not
  // exist.
  const base::FilePath file3 =
      temp_directory.GetPath().Append("file3");  // does not exist.
  EXPECT_FALSE(GetSha1HashOfFiles({file2, file3}, &hash));
  EXPECT_FALSE(GetSha1HashOfFiles({file3, file2}, &hash));
  EXPECT_FALSE(GetSha1HashOfFiles({file3}, &hash));
}

TEST(ArcSetupUtil, TestShouldDeleteAndroidData) {
  // Shouldn't delete data when no upgrade or downgrade.
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_M,
                                       AndroidSdkVersion::ANDROID_M));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_N_MR1,
                                       AndroidSdkVersion::ANDROID_N_MR1));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_P,
                                       AndroidSdkVersion::ANDROID_P));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                       AndroidSdkVersion::ANDROID_R));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S,
                                       AndroidSdkVersion::ANDROID_S));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S_V2,
                                       AndroidSdkVersion::ANDROID_S_V2));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_TIRAMISU,
                                       AndroidSdkVersion::ANDROID_TIRAMISU));

  // Shouldn't delete data for initial installation.
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_M,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_N_MR1,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_P,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S_V2,
                                       AndroidSdkVersion::UNKNOWN));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_TIRAMISU,
                                       AndroidSdkVersion::UNKNOWN));

  // Shouldn't delete data for expected upgrades.
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_N_MR1,
                                       AndroidSdkVersion::ANDROID_M));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_P,
                                       AndroidSdkVersion::ANDROID_N_MR1));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                       AndroidSdkVersion::ANDROID_P));
  EXPECT_FALSE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_TIRAMISU,
                                       AndroidSdkVersion::ANDROID_R));

  // All sorts of downgrades should delete data.
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_N_MR1,
                                      AndroidSdkVersion::ANDROID_P));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_M,
                                      AndroidSdkVersion::ANDROID_N_MR1));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_P,
                                      AndroidSdkVersion::ANDROID_R));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                      AndroidSdkVersion::ANDROID_S));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S,
                                      AndroidSdkVersion::ANDROID_S_V2));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                      AndroidSdkVersion::ANDROID_TIRAMISU));

  // Explicitly delete data when ARC++ is upgraded from M to >= P.
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_P,
                                      AndroidSdkVersion::ANDROID_M));

  // Explicitly delete data when ARC++ is upgraded from N to R.
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_R,
                                      AndroidSdkVersion::ANDROID_N_MR1));

  // Explicitly delete data when ARC++ is upgraded from P to S, S_V2 or
  // TIRAMISU.
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S,
                                      AndroidSdkVersion::ANDROID_P));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_S_V2,
                                      AndroidSdkVersion::ANDROID_P));
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_TIRAMISU,
                                      AndroidSdkVersion::ANDROID_P));

  // Delete data for upgrades from a release version to a development version.
  EXPECT_TRUE(ShouldDeleteAndroidData(AndroidSdkVersion::ANDROID_DEVELOPMENT,
                                      AndroidSdkVersion::ANDROID_R));
}

TEST(ArcSetupUtil, TestGetUserId) {
  uid_t uid = -1;
  gid_t gid = -1;
  EXPECT_FALSE(GetUserId("thisuserdoesntexist", &uid, &gid));
  EXPECT_TRUE(GetUserId("root", &uid, &gid));
  EXPECT_EQ(0, uid);
  EXPECT_EQ(0, gid);
  EXPECT_TRUE(GetUserId("android-root", &uid, &gid));
  EXPECT_EQ(655360, uid);
  EXPECT_EQ(655360, gid);
  if (USE_ARCVM) {
    EXPECT_TRUE(GetUserId("crosvm", &uid, &gid));
    EXPECT_NE(655360, uid);
    EXPECT_NE(655360, gid);
  }
}

TEST(ArcSetupUtil, SafeCopyFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath src_file = temp_dir.GetPath().Append("srcfile");

  // Create a new source file and write it.
  ASSERT_TRUE(WriteToFile(src_file, 0755, "testabc"));

  const base::FilePath dest_file =
      temp_dir.GetPath().Append("dest").Append("destfile");
  ASSERT_TRUE(SafeCopyFile(src_file, brillo::SafeFD::Root().first, dest_file,
                           brillo::SafeFD::Root().first));

  const base::FilePath symlink = temp_dir.GetPath().Append("symlink");
  ASSERT_TRUE(base::CreateSymbolicLink(dest_file, symlink));
  ASSERT_FALSE(SafeCopyFile(src_file, brillo::SafeFD::Root().first, symlink,
                            brillo::SafeFD::Root().first));
}

TEST(ArcSetupUtil, GenerateFirstStageFstab) {
  constexpr const char kFakeCombinedBuildPropPath[] = "/path/to/build.prop";
  constexpr const char kAnotherFakeCombinedBuildPropPath[] =
      "/foo/bar/baz.prop";
  constexpr const char kCachePartition[] = "/cache";

  std::string content;
  base::ScopedTempDir dir;
  ASSERT_TRUE(dir.CreateUniqueTempDir());
  const base::FilePath fstab(dir.GetPath().Append("fstab"));
  const base::FilePath vendor_image_path;
  std::string cache_partition;

  // Generate the fstab and verify the content.
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kFakeCombinedBuildPropPath), fstab,
                              vendor_image_path, cache_partition));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_NE(std::string::npos, content.find(kFakeCombinedBuildPropPath));
  EXPECT_EQ(std::string::npos, content.find(kCachePartition));

  // Generate the fstab again with the other prop file and verify the content.
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kAnotherFakeCombinedBuildPropPath),
                              fstab, vendor_image_path, cache_partition));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_EQ(std::string::npos, content.find(kFakeCombinedBuildPropPath));
  EXPECT_NE(std::string::npos, content.find(kAnotherFakeCombinedBuildPropPath));
  EXPECT_EQ(std::string::npos, content.find(kCachePartition));
}

TEST(ArcSetupUtil, GenerateFirstStageFstab_WithCachePartition) {
  constexpr const char kFakeCombinedBuildPropPath[] = "/path/to/build.prop";

  std::string content;
  base::ScopedTempDir dir;
  ASSERT_TRUE(dir.CreateUniqueTempDir());
  const base::FilePath fstab(dir.GetPath().Append("fstab"));
  const base::FilePath vendor_image_path;

  const std::string cache_partition = "vdc";
  // Generate the fstab and verify if the disk number for cache is correctly set
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kFakeCombinedBuildPropPath), fstab,
                              vendor_image_path, cache_partition));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_NE(std::string::npos, content.find(cache_partition));

  const std::string cache_partition_with_demo = "vdd";
  // Generate the fstab again with another disk number and verify the disk
  // number
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kFakeCombinedBuildPropPath), fstab,
                              vendor_image_path, cache_partition_with_demo));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_NE(std::string::npos, content.find(cache_partition_with_demo));
}

TEST(ArcSetupUtil, GenerateFirstStageFstab_VendorImageType) {
  constexpr const char kFakeCombinedBuildPropPath[] = "/path/to/build.prop";

  std::string content;
  base::ScopedTempDir dir;
  ASSERT_TRUE(dir.CreateUniqueTempDir());
  const base::FilePath fstab(dir.GetPath().Append("fstab"));
  const base::FilePath vendor_image_path(
      dir.GetPath().Append("vendor.raw.img"));
  std::string cache_partition;

  // By default, "squashfs" should be set as the vendor file system type.
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kFakeCombinedBuildPropPath), fstab,
                              vendor_image_path, cache_partition));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_EQ(0, content.find("/dev/block/vdb /vendor squashfs "));

  // Create a fake EROFS image, which has the EROFS magic number at 1024 byte.
  const uint32_t kErofsMagicNumber = 0xe0f5e1e2;
  base::ScopedFD fd(
      open(vendor_image_path.value().c_str(), O_CREAT | O_WRONLY, 0600));
  ASSERT_TRUE(fd.is_valid());
  ASSERT_EQ(lseek(fd.get(), 1024, SEEK_SET), 1024);
  const std::string data(reinterpret_cast<const char*>(&kErofsMagicNumber),
                         sizeof(kErofsMagicNumber));
  ASSERT_TRUE(base::WriteFileDescriptor(fd.get(), data));

  // Pass the fake EROFS image as |vendor_image_path|.
  // "erofs" should be set as the vendor file system type.
  EXPECT_TRUE(
      GenerateFirstStageFstab(base::FilePath(kFakeCombinedBuildPropPath), fstab,
                              vendor_image_path, cache_partition));
  EXPECT_TRUE(base::ReadFileToString(fstab, &content));
  EXPECT_EQ(0, content.find("/dev/block/vdb /vendor erofs "));
}

TEST_P(FilterMediaProfileTest, All) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  const base::FilePath test_config =
      temp_directory.GetPath().Append("test_config.json");
  if (GetParam().test_config_content) {
    ASSERT_TRUE(
        WriteToFile(test_config, 0644, *(GetParam().test_config_content)));
  }

  const base::FilePath media_profile =
      temp_directory.GetPath().Append("media_profiles.xml");
  ASSERT_TRUE(
      WriteToFile(media_profile, 0755, GetParam().media_profile_content));

  auto result = FilterMediaProfile(media_profile, test_config);
  ASSERT_TRUE(result);

  auto remove_space = [](const std::string& s) {
    return base::JoinString(
        base::SplitStringPiece(s, " \t\n", base::TRIM_WHITESPACE,
                               base::SPLIT_WANT_NONEMPTY),
        "");
  };

  ASSERT_EQ(remove_space(GetParam().result_content), remove_space(*result));
}

INSTANTIATE_TEST_SUITE_P(All,
                         FilterMediaProfileTest,
                         testing::ValuesIn(kFilterMediaProfileParam));

TEST_P(AppendFeatureManagementTest, All) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  const base::FilePath hardware_property_file =
      temp_directory.GetPath().Append("hw.xml");
  ASSERT_TRUE(WriteToFile(hardware_property_file, 0755,
                          GetParam().hardware_property_content));

  auto fake = std::make_unique<segmentation::fake::FeatureManagementFake>();
  segmentation::fake::FeatureManagementFake* fake_feature_management_ =
      fake.get();
  segmentation::FeatureManagement feature_management(std::move(fake));
  for (auto feature = GetParam().test_features.begin();
       feature != GetParam().test_features.end(); feature++) {
    fake_feature_management_->SetFeature(*feature, segmentation::USAGE_ANDROID);
  }
  auto result =
      AppendFeatureManagement(hardware_property_file, feature_management);
  ASSERT_TRUE(result);
  auto remove_space = [](const std::string& s) {
    return base::JoinString(
        base::SplitStringPiece(s, " \t\n", base::TRIM_WHITESPACE,
                               base::SPLIT_WANT_NONEMPTY),
        "");
  };

  ASSERT_EQ(remove_space(GetParam().result_content), remove_space(*result));
}

INSTANTIATE_TEST_SUITE_P(All,
                         AppendFeatureManagementTest,
                         testing::ValuesIn(kAppendFeatureManagementParam));

}  // namespace arc
