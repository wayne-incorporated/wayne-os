// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/strings/utf_string_conversion_utils.h>
#include <base/third_party/icu/icu_utf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "authpolicy/samba_helper.h"
#include "authpolicy/samba_interface.h"

namespace {

// See e.g.
// http://stackoverflow.com/questions/1545630/searching-for-a-objectguid-in-ad.
const char kGuid[] = "10a9cbf6-3a09-444c-a5f6-95dd0b94e3ae";
const char kOctetStr[] =
    "\\F6\\CB\\A9\\10\\09\\3A\\4C\\44\\A5\\F6\\95\\DD\\0B\\94\\E3\\AE";

const char kInvalidGuid[] = "10a9cbf6-3a09-444c-a5f6";

// Filled by the unit tests.
const std::vector<uint16_t>* g_rand_buffer = nullptr;

// Fills data with values from g_rand_buffer, padded periodically.
void TestingRandBytes(void* data, size_t data_size) {
  ASSERT_NE(nullptr, g_rand_buffer);
  ASSERT_GT(g_rand_buffer->size(), 0);
  uint16_t* data16 = static_cast<uint16_t*>(data);
  size_t data_size16 = data_size / sizeof(uint16_t);
  for (size_t n = 0; n < data_size16; ++n)
    data16[n] = g_rand_buffer->at(n % g_rand_buffer->size());
}

}  // namespace

namespace authpolicy {

class SambaHelperTest : public ::testing::Test {
 public:
  SambaHelperTest() {}
  SambaHelperTest(const SambaHelperTest&) = delete;
  SambaHelperTest& operator=(const SambaHelperTest&) = delete;
  ~SambaHelperTest() override {}

 protected:
  // Helpers for ParseUserPrincipleName.
  std::string user_name_;
  std::string realm_;
  std::string normalized_upn_;

  bool ParseUserPrincipalName(const char* user_principal_name_) {
    return ::authpolicy::ParseUserPrincipalName(
        user_principal_name_, &user_name_, &realm_, &normalized_upn_);
  }

  // Helpers for FindToken.
  std::string find_token_result_;

  bool FindToken(const char* in_str, char token_separator, const char* token) {
    return ::authpolicy::FindToken(in_str, token_separator, token,
                                   &find_token_result_);
  }

  // Helpers for ParseGpoVersion
  uint32_t gpo_version_ = 0;

  // Helpers for ParseGpFLags
  int gp_flags_ = kGpFlagInvalid;
};

// a@b.c succeeds.
TEST_F(SambaHelperTest, ParseUPNSuccess) {
  EXPECT_TRUE(ParseUserPrincipalName("usar@wokgroup.doomain"));
  EXPECT_EQ(user_name_, "usar");
  EXPECT_EQ(realm_, "WOKGROUP.DOOMAIN");
  EXPECT_EQ(normalized_upn_, "usar@WOKGROUP.DOOMAIN");
}

// a@b.c.d.e succeeds.
TEST_F(SambaHelperTest, ParseUPNSuccess_Long) {
  EXPECT_TRUE(ParseUserPrincipalName("usar@wokgroup.doomain.company.com"));
  EXPECT_EQ(user_name_, "usar");
  EXPECT_EQ(realm_, "WOKGROUP.DOOMAIN.COMPANY.COM");
  EXPECT_EQ(normalized_upn_, "usar@WOKGROUP.DOOMAIN.COMPANY.COM");
}

// Capitalization works as expected.
TEST_F(SambaHelperTest, ParseUPNSuccess_MixedCaps) {
  EXPECT_TRUE(ParseUserPrincipalName("UsAr@WoKgrOUP.DOOMain.com"));
  EXPECT_EQ(user_name_, "UsAr");
  EXPECT_EQ(realm_, "WOKGROUP.DOOMAIN.COM");
  EXPECT_EQ(normalized_upn_, "UsAr@WOKGROUP.DOOMAIN.COM");
}

// a.b@c.d succeeds, even though it is invalid (rejected by kinit).
TEST_F(SambaHelperTest, ParseUPNSuccess_DotAtDot) {
  EXPECT_TRUE(ParseUserPrincipalName("usar.team@wokgroup.doomain"));
  EXPECT_EQ(user_name_, "usar.team");
  EXPECT_EQ(realm_, "WOKGROUP.DOOMAIN");
  EXPECT_EQ(normalized_upn_, "usar.team@WOKGROUP.DOOMAIN");
}

// a@ fails (no workgroup.domain).
TEST_F(SambaHelperTest, ParseUPNFail_NoRealm) {
  EXPECT_FALSE(ParseUserPrincipalName("usar@"));
}

// a fails (no @workgroup.domain).
TEST_F(SambaHelperTest, ParseUPNFail_NoAtRealm) {
  EXPECT_FALSE(ParseUserPrincipalName("usar"));
}

// a. fails (no @workgroup.domain and trailing . is invalid, anyway).
TEST_F(SambaHelperTest, ParseUPNFail_NoAtRealmButDot) {
  EXPECT_FALSE(ParseUserPrincipalName("usar."));
}

// a@b@c fails (double at).
TEST_F(SambaHelperTest, ParseUPNFail_AtAt) {
  EXPECT_FALSE(ParseUserPrincipalName("usar@wokgroup@doomain"));
}

// a@b@c fails (double at).
TEST_F(SambaHelperTest, ParseUPNFail_AtAtDot) {
  EXPECT_FALSE(ParseUserPrincipalName("usar@wokgroup@doomain.com"));
}

// @b.c fails (empty user name).
TEST_F(SambaHelperTest, ParseUPNFail_NoUpn) {
  EXPECT_FALSE(ParseUserPrincipalName("@wokgroup.doomain"));
}

// b.c fails (no user name@).
TEST_F(SambaHelperTest, ParseUPNFail_NoUpnAt) {
  EXPECT_FALSE(ParseUserPrincipalName("wokgroup.doomain"));
}

// .b.c fails (no user name@ and initial . is invalid, anyway).
TEST_F(SambaHelperTest, ParseUPNFail_NoUpnAtButDot) {
  EXPECT_FALSE(ParseUserPrincipalName(".wokgroup.doomain"));
}

// a=b works.
TEST_F(SambaHelperTest, FindTokenSuccess) {
  EXPECT_TRUE(FindToken("tok=res", '=', "tok"));
  EXPECT_EQ(find_token_result_, "res");
}

// Multiple matches return the first match
TEST_F(SambaHelperTest, FindTokenSuccess_Multiple) {
  EXPECT_TRUE(FindToken("tok=res\ntok=res2", '=', "tok"));
  EXPECT_EQ(find_token_result_, "res");
}

// Different separators are ignored matches return the first match
TEST_F(SambaHelperTest, FindTokenSuccess_IgnoreInvalidSeparator) {
  EXPECT_TRUE(FindToken("tok:res\ntok=res2", '=', "tok"));
  EXPECT_EQ(find_token_result_, "res2");
}

// a=b=c returns b=c
TEST_F(SambaHelperTest, FindTokenSuccess_TwoSeparators) {
  EXPECT_TRUE(FindToken("tok = res = true", '=', "tok"));
  EXPECT_EQ(find_token_result_, "res = true");
}

// Trims leading and trailing whitespace
TEST_F(SambaHelperTest, FindTokenSuccess_TrimWhitespace) {
  EXPECT_TRUE(FindToken("\n   \n\n tok  =  res   \n\n", '=', "tok"));
  EXPECT_EQ(find_token_result_, "res");
}

// Empty input strings fail.
TEST_F(SambaHelperTest, FindTokenFail_Empty) {
  EXPECT_FALSE(FindToken("", '=', "tok"));
  EXPECT_FALSE(FindToken("\n", '=', "tok"));
  EXPECT_FALSE(FindToken("\n\n\n", '=', "tok"));
}

// Whitespace input strings fail.
TEST_F(SambaHelperTest, FindTokenFail_Whitespace) {
  EXPECT_FALSE(FindToken("    ", '=', "tok"));
  EXPECT_FALSE(FindToken("    \n   \n ", '=', "tok"));
  EXPECT_FALSE(FindToken("    \n\n \n   ", '=', "tok"));
}

// a=b works.
TEST_F(SambaHelperTest, FindTokenInLineSuccess) {
  std::string result;
  EXPECT_TRUE(
      authpolicy::FindTokenInLine("  tok =  res ", '=', "tok", &result));
  EXPECT_EQ(result, "res");
}

// Parsing valid GPO version strings.
TEST_F(SambaHelperTest, ParseGpoVersionSuccess) {
  EXPECT_TRUE(ParseGpoVersion("0 (0x0000)", &gpo_version_));
  EXPECT_EQ(gpo_version_, 0);
  EXPECT_TRUE(ParseGpoVersion("1 (0x0001)", &gpo_version_));
  EXPECT_EQ(gpo_version_, 1);
  EXPECT_TRUE(ParseGpoVersion("9 (0x0009)", &gpo_version_));
  EXPECT_EQ(gpo_version_, 9);
  EXPECT_TRUE(ParseGpoVersion("15 (0x000f)", &gpo_version_));
  EXPECT_EQ(gpo_version_, 15);
  EXPECT_TRUE(ParseGpoVersion("65535 (0xffff)", &gpo_version_));
  EXPECT_EQ(gpo_version_, 0xffff);
}

// Empty string
TEST_F(SambaHelperTest, ParseGpoVersionFail_EmptyString) {
  EXPECT_FALSE(ParseGpoVersion("", &gpo_version_));
}

// Base-10 and Base-16 (hex) numbers not matching
TEST_F(SambaHelperTest, ParseGpoVersionFail_NotMatching) {
  EXPECT_FALSE(ParseGpoVersion("15 (0x000e)", &gpo_version_));
}

// Non-numeric characters fail
TEST_F(SambaHelperTest, ParseGpoVersionFail_NonNumericCharacters) {
  EXPECT_FALSE(ParseGpoVersion("15a (0x00f)", &gpo_version_));
  EXPECT_FALSE(ParseGpoVersion("15 (0xg0f)", &gpo_version_));
  EXPECT_FALSE(ParseGpoVersion("dead", &gpo_version_));
}

// Missing 0x in hex string fails
TEST_F(SambaHelperTest, ParseGpoVersionFail_Missing0x) {
  EXPECT_FALSE(ParseGpoVersion("15 (000f)", &gpo_version_));
}

// Missing brackets in hex string fail
TEST_F(SambaHelperTest, ParseGpoVersionFail_MissingBrackets) {
  EXPECT_FALSE(ParseGpoVersion("15 000f", &gpo_version_));
}

// Missing hex string fails
TEST_F(SambaHelperTest, ParseGpoVersionFail_MissingHex) {
  EXPECT_FALSE(ParseGpoVersion("10", &gpo_version_));
}

// Only hex string fails
TEST_F(SambaHelperTest, ParseGpoVersionFail_HexOnly) {
  EXPECT_FALSE(ParseGpoVersion("0x000f", &gpo_version_));
}

// Only hex string in brackets fails
TEST_F(SambaHelperTest, ParseGpoVersionFail_BracketsHexOnly) {
  EXPECT_FALSE(ParseGpoVersion("(0x000f)", &gpo_version_));
}

// Successfully parsing GP flags
TEST_F(SambaHelperTest, ParseGpFlagsSuccess) {
  EXPECT_TRUE(ParseGpFlags("0 GPFLAGS_ALL_ENABLED", &gp_flags_));
  EXPECT_EQ(0, gp_flags_);
  EXPECT_TRUE(ParseGpFlags("1 GPFLAGS_USER_SETTINGS_DISABLED", &gp_flags_));
  EXPECT_EQ(1, gp_flags_);
  EXPECT_TRUE(ParseGpFlags("2 GPFLAGS_MACHINE_SETTINGS_DISABLED", &gp_flags_));
  EXPECT_EQ(2, gp_flags_);
  EXPECT_TRUE(ParseGpFlags("3 GPFLAGS_ALL_DISABLED", &gp_flags_));
  EXPECT_EQ(3, gp_flags_);
}

// Strings don't match numbers
TEST_F(SambaHelperTest, ParseGpFlagsFail_StringNotMatching) {
  EXPECT_FALSE(ParseGpFlags("1 GPFLAGS_ALL_ENABLED", &gp_flags_));
  EXPECT_FALSE(ParseGpFlags("2 GPFLAGS_ALL_DISABLED", &gp_flags_));
}

// Missing string
TEST_F(SambaHelperTest, ParseGpFlagsFail_MissingString) {
  EXPECT_FALSE(ParseGpFlags("0", &gp_flags_));
}

// Missing number
TEST_F(SambaHelperTest, ParseGpFlagsFail_MissingNumber) {
  EXPECT_FALSE(ParseGpFlags("GPFLAGS_ALL_ENABLED", &gp_flags_));
}

// String not trimmed
TEST_F(SambaHelperTest, ParseGpFlagsFail_NotTrimmed) {
  EXPECT_FALSE(ParseGpFlags(" 0 GPFLAGS_ALL_ENABLED", &gp_flags_));
  EXPECT_FALSE(ParseGpFlags("0 GPFLAGS_ALL_ENABLED ", &gp_flags_));
}

// Valid GUID to octet string conversion.
TEST_F(SambaHelperTest, GuidToOctetSuccess) {
  EXPECT_EQ(kOctetStr, GuidToOctetString(kGuid));
}

// Invalid GUID to octet string conversion should yield empty string.
TEST_F(SambaHelperTest, GuidToOctetFailInvalidGuid) {
  EXPECT_EQ("", GuidToOctetString(kInvalidGuid));
}

// OctetStringToGuidForTesting() reverses GuidToOctetString().
TEST_F(SambaHelperTest, OctetToGuidSuccess) {
  const std::string octet_str = GuidToOctetString(kGuid);
  EXPECT_EQ(kGuid, OctetStringToGuidForTesting(octet_str));
}

// BuildDistinguishedName() builds a valid distinguished name.
TEST_F(SambaHelperTest, BuildDistinguishedName) {
  std::vector<std::string> ou_vector;
  std::string domain = "example.com";

  ou_vector = {"OU1"};
  EXPECT_EQ("ou=OU1,dc=example,dc=com",
            BuildDistinguishedName(ou_vector, domain));

  ou_vector.clear();
  EXPECT_EQ("dc=example,dc=com", BuildDistinguishedName(ou_vector, domain));

  ou_vector = {"OU1", "OU2", "OU3"};
  EXPECT_EQ("ou=OU1,ou=OU2,ou=OU3,dc=example,dc=com",
            BuildDistinguishedName(ou_vector, domain));

  ou_vector = {"ou=123!", "a\"b", " ", "# ", " #", ",,\n\n\r/"};
  domain.clear();
  EXPECT_EQ(
      "ou=ou\\=123!,ou=a\\\"b,ou=\\ ,ou=\\#\\ ,ou=\\ "
      "#,ou=\\,\\,\\\n\\\n\\\r\\/",
      BuildDistinguishedName(ou_vector, domain));

  domain.clear();
  ou_vector = {"ou"};
  EXPECT_EQ("ou=ou", BuildDistinguishedName(ou_vector, domain));

  ou_vector.clear();
  EXPECT_EQ("", BuildDistinguishedName(ou_vector, domain));
}

// Tests basic properties of random machine passwords.
TEST_F(SambaHelperTest, GenerateRandomMachinePassword) {
  const std::string password = GenerateRandomMachinePassword();

  // 256 code points with at most 3 bytes per code point since each code point
  // is <= 0xFFFF.
  EXPECT_GE(kMachinePasswordCodePoints * 3, password.size());

  // Verify that code points are in a valid range.
  base_icu::UChar32 code_point = UINT32_MAX;
  size_t num_code_points = 0;
  for (size_t char_index = 0; char_index < password.size(); ++char_index) {
    EXPECT_TRUE(base::ReadUnicodeCharacter(password.data(), password.size(),
                                           &char_index, &code_point));
    // In the basic multilingual plane (BMP).
    EXPECT_LE(code_point, 0xFFFF);

    // Not an invalid code point.
    EXPECT_TRUE(base::IsValidCodepoint(code_point));

    // Not a NULL character.
    EXPECT_NE(0, code_point);

    ++num_code_points;
  }
  EXPECT_EQ(kMachinePasswordCodePoints, num_code_points);
}

// Since GenerateRandomMachinePassword is random and might be flaky, let's add
// some deterministic tests as well.
TEST_F(SambaHelperTest, GenerateRandomMachinePasswordExcludeSurrogates) {
  // Code points between 0xD800 and 0xDFFF are invalid.
  const std::vector<uint16_t> data = {'H',    'E',    'L',    0xD799, 0xD800,
                                      0xD801, 0xDBFE, 0xDBFF, 0xDC00, 0xDC01,
                                      0xDFFE, 0xDFFF, 0xE000, 'L',    'O'};
  g_rand_buffer = &data;
  SetRandomNumberGeneratorForTesting(&TestingRandBytes);

  // Only 0xD799 and 0xE000 should be converted to UTF8, the ones in between
  // should be ignored.
  const std::string password = GenerateRandomMachinePassword();
  std::string expected_start = "HEL";
  base::WriteUnicodeCharacter(0xD799, &expected_start);
  base::WriteUnicodeCharacter(0xE000, &expected_start);
  expected_start += "LO";
  EXPECT_EQ(expected_start, password.substr(0, expected_start.size()));

  SetRandomNumberGeneratorForTesting(nullptr);
  g_rand_buffer = nullptr;
}

TEST_F(SambaHelperTest, GenerateRandomMachinePasswordExcludeNullAndNewline) {
  const std::vector<uint16_t> data = {'H', 'E', 'L', '\n', 'L', 'O', '\0'};
  g_rand_buffer = &data;
  SetRandomNumberGeneratorForTesting(&TestingRandBytes);

  // The \n and \0 should be ignored and data is padded periodically.
  const std::string password = GenerateRandomMachinePassword();
  constexpr char expected_start[] = "HELLOHELLOHELLO";
  EXPECT_EQ(std::string(password.data()), password);
  EXPECT_EQ(expected_start, password.substr(0, strlen(expected_start)));

  SetRandomNumberGeneratorForTesting(nullptr);
  g_rand_buffer = nullptr;
}

}  // namespace authpolicy
