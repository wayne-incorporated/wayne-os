// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/ui/chromium_command_builder.h"

#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "chromeos/ui/util.h"

namespace chromeos {
namespace ui {

class ChromiumCommandBuilderTest : public testing::Test {
 public:
  ChromiumCommandBuilderTest()
      : write_use_flags_file_(true), write_lsb_release_file_(true) {
    PCHECK(temp_dir_.CreateUniqueTempDir());
    base_path_ = temp_dir_.GetPath();
    builder_.set_base_path_for_testing(base_path_);

    pepper_dir_ = util::GetReparentedPath(
        ChromiumCommandBuilder::kPepperPluginsPath, base_path_);
    PCHECK(base::CreateDirectory(pepper_dir_));
  }
  ChromiumCommandBuilderTest(const ChromiumCommandBuilderTest&) = delete;
  ChromiumCommandBuilderTest& operator=(const ChromiumCommandBuilderTest&) =
      delete;

  virtual ~ChromiumCommandBuilderTest() {}

  // Does testing-related initialization and returns the result of |builder_|'s
  // Init() method.
  bool Init() {
    if (write_use_flags_file_) {
      WriteFileUnderBasePath(ChromiumCommandBuilder::kUseFlagsPath,
                             use_flags_data_);
    }
    if (write_lsb_release_file_) {
      WriteFileUnderBasePath(ChromiumCommandBuilder::kLsbReleasePath,
                             lsb_release_data_);
    }
    return builder_.Init();
  }

  // Writes |data| to |path| underneath |base_path_|.
  void WriteFileUnderBasePath(const std::string& path,
                              const std::string& data) {
    base::FilePath reparented_path(util::GetReparentedPath(path, base_path_));
    if (!base::DirectoryExists(reparented_path.DirName()))
      PCHECK(base::CreateDirectory(reparented_path.DirName()));
    PCHECK(base::WriteFile(reparented_path, data.data(), data.size()) ==
           static_cast<int>(data.size()));
  }

  // Looks up |name| in |builder_|'s list of environment variables, returning
  // its value if present or an empty string otherwise.
  std::string ReadEnvVar(const std::string& name) {
    const ChromiumCommandBuilder::StringMap& vars =
        builder_.environment_variables();
    ChromiumCommandBuilder::StringMap::const_iterator it = vars.find(name);
    return it != vars.end() ? it->second : std::string();
  }

  // Returns the first argument in |builder_| that starts with |prefix|, or an
  // empty string if no matching argument is found.
  std::string GetFirstArgWithPrefix(const std::string& prefix) {
    const ChromiumCommandBuilder::StringVector& args = builder_.arguments();
    for (size_t i = 0; i < args.size(); ++i) {
      if (args[i].find(prefix) == 0)
        return args[i];
    }
    return std::string();
  }

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath base_path_;

  bool write_use_flags_file_;
  std::string use_flags_data_;

  bool write_lsb_release_file_;
  std::string lsb_release_data_;

  base::FilePath pepper_dir_;

  ChromiumCommandBuilder builder_;
};

TEST_F(ChromiumCommandBuilderTest, MissingUseFlagsFile) {
  write_use_flags_file_ = false;
  EXPECT_FALSE(Init());
}

TEST_F(ChromiumCommandBuilderTest, UseFlags) {
  use_flags_data_ = "# Here's a comment.\nfoo\nbar\n";
  ASSERT_TRUE(Init());

  EXPECT_TRUE(builder_.UseFlagIsSet("foo"));
  EXPECT_TRUE(builder_.UseFlagIsSet("bar"));
  EXPECT_FALSE(builder_.UseFlagIsSet("food"));
  EXPECT_FALSE(builder_.UseFlagIsSet("# Here's a comment."));
  EXPECT_FALSE(builder_.UseFlagIsSet("#"));
  EXPECT_FALSE(builder_.UseFlagIsSet("a"));
}

TEST_F(ChromiumCommandBuilderTest, MissingLsbReleaseFile) {
  write_lsb_release_file_ = false;
  EXPECT_FALSE(Init());
}

TEST_F(ChromiumCommandBuilderTest, LsbRelease) {
  lsb_release_data_ = "abc\ndef";
  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());

  EXPECT_EQ(lsb_release_data_, ReadEnvVar("LSB_RELEASE"));
  EXPECT_FALSE(ReadEnvVar("LSB_RELEASE_TIME").empty());
  EXPECT_FALSE(builder_.is_test_build());
}

TEST_F(ChromiumCommandBuilderTest, IsTestBuild) {
  lsb_release_data_ = "abc\nCHROMEOS_RELEASE_TRACK=testabc\ndef";
  ASSERT_TRUE(Init());
  EXPECT_TRUE(builder_.is_test_build());
}

TEST_F(ChromiumCommandBuilderTest, TimeZone) {
  // Test that the builder creates a symlink for the time zone.
  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());
  const base::FilePath kSymlink(util::GetReparentedPath(
      ChromiumCommandBuilder::kTimeZonePath, base_path_));
  base::FilePath target;
  ASSERT_TRUE(base::ReadSymbolicLink(kSymlink, &target));
  EXPECT_EQ(ChromiumCommandBuilder::kDefaultZoneinfoPath, target.value());

  // Delete the old symlink and create a new one with a different target.
  // Arbitrarily use |base_path_| (we need a path that exists).
  ASSERT_TRUE(base::DeleteFile(kSymlink));
  const base::FilePath kNewTarget(base_path_);
  ASSERT_TRUE(base::CreateSymbolicLink(kNewTarget, kSymlink));

  // Initialize a second builder and check that it leaves the existing symlink
  // alone.
  ChromiumCommandBuilder second_builder;
  second_builder.set_base_path_for_testing(base_path_);
  ASSERT_TRUE(second_builder.Init());
  ASSERT_TRUE(second_builder.SetUpChromium());
  ASSERT_TRUE(base::ReadSymbolicLink(kSymlink, &target));
  EXPECT_EQ(kNewTarget.value(), target.value());
}

TEST_F(ChromiumCommandBuilderTest, BasicEnvironment) {
  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());

  EXPECT_EQ("chronos", ReadEnvVar("USER"));
  EXPECT_EQ("chronos", ReadEnvVar("LOGNAME"));
  EXPECT_EQ("/bin/sh", ReadEnvVar("SHELL"));
  EXPECT_FALSE(ReadEnvVar("PATH").empty());
  base::FilePath data_dir(util::GetReparentedPath("/home/chronos", base_path_));
  EXPECT_EQ(data_dir.value(), ReadEnvVar("DATA_DIR"));
  EXPECT_TRUE(base::DirectoryExists(data_dir));
}

TEST_F(ChromiumCommandBuilderTest, ValueListFlags) {
  use_flags_data_ = "floss";

  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());

  // All of these methods do essentially the same thing.
  typedef void (ChromiumCommandBuilder::*AddMethod)(const std::string&);
  struct TestCase {
    const char* flag;
    AddMethod method;
    bool append;
  };
  const std::vector<TestCase> kTestCases = {
      {ChromiumCommandBuilder::kVmoduleFlag,
       &ChromiumCommandBuilder::AddVmodulePattern, false},
      {ChromiumCommandBuilder::kEnableFeaturesFlag,
       &ChromiumCommandBuilder::AddFeatureEnableOverride, true},
      {ChromiumCommandBuilder::kDisableFeaturesFlag,
       &ChromiumCommandBuilder::AddFeatureDisableOverride, true},
      {ChromiumCommandBuilder::kEnableBlinkFeaturesFlag,
       &ChromiumCommandBuilder::AddBlinkFeatureEnableOverride, true},
      {ChromiumCommandBuilder::kDisableBlinkFeaturesFlag,
       &ChromiumCommandBuilder::AddBlinkFeatureDisableOverride, true},
  };

  for (const auto& tc : kTestCases) {
    SCOPED_TRACE(tc.flag);
    const std::string kPrefix = base::StringPrintf("--%s=", tc.flag);
    EXPECT_EQ("", GetFirstArgWithPrefix(kPrefix));
    (builder_.*(tc.method))("foo");
    EXPECT_EQ(kPrefix + "foo", GetFirstArgWithPrefix(kPrefix));
    (builder_.*(tc.method))("bar");
    EXPECT_EQ(kPrefix + (tc.append ? "foo,bar" : "bar,foo"),
              GetFirstArgWithPrefix(kPrefix));

    // Add another argument and check that the flag still gets updated.
    builder_.AddArg("--blah");
    (builder_.*(tc.method))("baz");
    ASSERT_EQ(kPrefix + (tc.append ? "foo,bar,baz" : "baz,bar,foo"),
              GetFirstArgWithPrefix(kPrefix));
  }
}

TEST_F(ChromiumCommandBuilderTest, UserConfig) {
  ASSERT_TRUE(Init());
  builder_.AddArg("--baz=4");
  builder_.AddArg("--blah-a");
  builder_.AddArg("--blah-b");

  const char kConfig[] =
      "# Here's a comment followed by a blank line and some whitespace.\n"
      "\n"
      "     \n"
      "--foo=1\n"
      "--bar=2\n"
      "FOO=3\n"
      "BAR=4\n"
      "!--bar\n"
      "!--baz\n"
      "--bar=3\n"
      "!--blah\n";
  base::FilePath path(util::GetReparentedPath("/config.txt", base_path_));
  ASSERT_EQ(strlen(kConfig), base::WriteFile(path, kConfig, strlen(kConfig)));
  std::set<std::string> disallowed_prefixes;

  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  ASSERT_EQ(2U, builder_.arguments().size());
  EXPECT_EQ("--foo=1", builder_.arguments()[0]);
  EXPECT_EQ("--bar=3", builder_.arguments()[1]);
  EXPECT_EQ("3", ReadEnvVar("FOO"));
  EXPECT_EQ("4", ReadEnvVar("BAR"));
}

TEST_F(ChromiumCommandBuilderTest, UserConfigWithDisallowedPrefixes) {
  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());

  size_t default_size = builder_.arguments().size();

  const char kConfig[] =
      "# Here's a comment followed by 3 lines with disallowed prefixes and\n"
      "# 2 lines without disallowed prefixes.\n"
      "--disallowed-prefix1=bar\n"
      "  --disallowed-prefix2=bar\n"
      "--notallowed-prefix3=bar\n"
      "--Disallowed-prefix=foo\n"
      "--allowed-prefix=foo";

  base::FilePath path(util::GetReparentedPath("/config.txt", base_path_));
  ASSERT_EQ(strlen(kConfig), base::WriteFile(path, kConfig, strlen(kConfig)));
  std::set<std::string> disallowed_prefixes;

  disallowed_prefixes.insert("--disallowed-prefix");
  disallowed_prefixes.insert("--notallowed-prefix");
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));

  ASSERT_EQ(default_size + 2, builder_.arguments().size());
  EXPECT_EQ("--Disallowed-prefix=foo", builder_.arguments()[default_size]);
  EXPECT_EQ("--allowed-prefix=foo", builder_.arguments()[default_size + 1]);
}

TEST_F(ChromiumCommandBuilderTest, UserConfigVmodule) {
  const char kPrefix[] = "--vmodule=";

  ASSERT_TRUE(Init());
  builder_.AddArg("--foo");
  builder_.AddVmodulePattern("a=2");
  builder_.AddArg("--bar");

  // Check that we don't get confused when deleting flags surrounding the
  // vmodule flag.
  const char kConfig[] = "!--foo\n!--bar";
  base::FilePath path(util::GetReparentedPath("/config.txt", base_path_));
  ASSERT_EQ(strlen(kConfig), base::WriteFile(path, kConfig, strlen(kConfig)));
  std::set<std::string> disallowed_prefixes;

  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  builder_.AddVmodulePattern("b=1");
  ASSERT_EQ("--vmodule=b=1,a=2", GetFirstArgWithPrefix(kPrefix));

  // Delete the --vmodule flag.
  const char kConfig2[] = "!--vmodule=";
  ASSERT_EQ(strlen(kConfig2),
            base::WriteFile(path, kConfig2, strlen(kConfig2)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  EXPECT_TRUE(builder_.arguments().empty());

  // Now add another vmodule pattern and check that the flag is re-added.
  builder_.AddVmodulePattern("c=1");
  ASSERT_EQ("--vmodule=c=1", GetFirstArgWithPrefix(kPrefix));

  // Check that vmodule directives in config files are handled.
  const char kConfig3[] = "vmodule=a=1\nvmodule=b=2";
  ASSERT_EQ(strlen(kConfig3),
            base::WriteFile(path, kConfig3, strlen(kConfig3)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  ASSERT_EQ("--vmodule=b=2,a=1,c=1", GetFirstArgWithPrefix(kPrefix));

  // Also check that literal "vmodule=..." arguments don't get added.
  ASSERT_EQ("", GetFirstArgWithPrefix("vmodule="));

  // "--vmodule=" lines in config files should be permitted too. Each pattern is
  // prepended to the existing list because Chrome uses the first matching
  // pattern that it sees; we want patterns specified via the developer's config
  // file to override hardcoded patterns.
  const char kConfig4[] = "--vmodule=d=1,e=2";
  ASSERT_EQ(strlen(kConfig4),
            base::WriteFile(path, kConfig4, strlen(kConfig4)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  ASSERT_EQ("--vmodule=e=2,d=1,b=2,a=1,c=1", GetFirstArgWithPrefix(kPrefix));
}

TEST_F(ChromiumCommandBuilderTest, UserConfigEnableFeatures) {
  const char kPrefix[] = "--enable-features=";

  ASSERT_TRUE(Init());
  builder_.AddArg("--foo");
  builder_.AddFeatureEnableOverride("a");
  builder_.AddArg("--bar");

  // Check that we don't get confused when deleting flags surrounding the
  // feature flag.
  const char kConfig[] = "!--foo\n!--bar";
  std::set<std::string> disallowed_prefixes;

  base::FilePath path(util::GetReparentedPath("/config.txt", base_path_));
  ASSERT_EQ(strlen(kConfig), base::WriteFile(path, kConfig, strlen(kConfig)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  builder_.AddFeatureEnableOverride("b");
  ASSERT_EQ("--enable-features=a,b", GetFirstArgWithPrefix(kPrefix));

  // Delete the --enable-features flag.
  const char kConfig2[] = "!--enable-features=";
  ASSERT_EQ(strlen(kConfig2),
            base::WriteFile(path, kConfig2, strlen(kConfig2)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  EXPECT_TRUE(builder_.arguments().empty());

  // Now add another feature and check that the flag is re-added.
  builder_.AddFeatureEnableOverride("c");
  ASSERT_EQ("--enable-features=c", GetFirstArgWithPrefix(kPrefix));

  // Check that enable-features directives in config files are handled.
  const char kConfig3[] = "enable-features=d\nenable-features=e";
  ASSERT_EQ(strlen(kConfig3),
            base::WriteFile(path, kConfig3, strlen(kConfig3)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  ASSERT_EQ("--enable-features=c,d,e", GetFirstArgWithPrefix(kPrefix));

  // Also check that literal "enable-features=..." arguments don't get added.
  ASSERT_EQ("", GetFirstArgWithPrefix("enable-features="));

  // "--enable-features=" lines in config files should be permitted too.
  const char kConfig4[] = "--enable-features=f,g";
  ASSERT_EQ(strlen(kConfig4),
            base::WriteFile(path, kConfig4, strlen(kConfig4)));
  ASSERT_TRUE(builder_.ApplyUserConfig(path, disallowed_prefixes));
  ASSERT_EQ("--enable-features=c,d,e,f,g", GetFirstArgWithPrefix(kPrefix));
}

TEST_F(ChromiumCommandBuilderTest, PepperPlugins) {
  const char kNetflix[] =
      "FILE_NAME=/opt/google/chrome/pepper/netflix.so\n"
      "PLUGIN_NAME=\"Netflix\"\n"
      "VERSION=2.0.0\n"
      "DESCRIPTION=Helper for the Netflix application\n"
      "MIME_TYPES=\"application/netflix\"\n";
  ASSERT_EQ(strlen(kNetflix),
            base::WriteFile(pepper_dir_.Append("netflix.info"), kNetflix,
                            strlen(kNetflix)));

  const char kOther[] =
      "PLUGIN_NAME=Some other plugin\n"
      "FILE_NAME=/opt/google/chrome/pepper/other.so\n";
  ASSERT_EQ(strlen(kOther), base::WriteFile(pepper_dir_.Append("other.info"),
                                            kOther, strlen(kOther)));

  const char kMissingFileName[] =
      "PLUGIN_NAME=Foo\n"
      "VERSION=2.3\n";
  ASSERT_EQ(strlen(kMissingFileName),
            base::WriteFile(pepper_dir_.Append("broken.info"), kMissingFileName,
                            strlen(kMissingFileName)));

  ASSERT_TRUE(Init());
  ASSERT_TRUE(builder_.SetUpChromium());

  // Plugins are ordered alphabetically by registration info.
  const char kExpected[] =
      "--register-pepper-plugins="
      "/opt/google/chrome/pepper/netflix.so#Netflix#"
      "Helper for the Netflix application#2.0.0;application/netflix,"
      "/opt/google/chrome/pepper/other.so#Some other plugin;";
  EXPECT_EQ(kExpected, GetFirstArgWithPrefix("--register-pepper-plugins"));
}

}  // namespace ui
}  // namespace chromeos
