// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/config_parser.h"

#include <ostream>
#include <string>

#include <base/logging.h>
#include <base/notreached.h>
#include <gtest/gtest.h>

#include "kerberos/kerberos_metrics.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace kerberos {
namespace {
constexpr char kCompleteKrb5Conf[] = R"(
# Comment
; Another comment

[libdefaults]
  clockskew = 123
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  renew_lifetime* = 7d
  ticket_lifetime* = 1d
  A.EXAMPLE.COM = {
    clockskew = 300
  }
  B.EXAMPLE.COM =
  {
    ; Tests = whether { can be on new line
    clockskew = 500
  }

[realms]
  kdc = 5.6.7.8
  EXAMPLE.COM = {
    kdc = 1.2.3.4
    admin_server = kdc.example.com
    auth_to_local = RULE:[2:$1](johndoe)s/^.*$/guest/
    auth_to_local_names = {
      hans = jack
      joerg = jerk
    }
  }*

[domain_realm]*
  any.thing = IS.ACCEPTED.HERE

[capaths]
    here = AS.WELL)";

std::string GenerateNestedGroups(int count) {
  std::string result;
  for (int i = 0; i < count; i++) {
    result += "A={\n";
  }
  for (int i = 0; i < count; i++) {
    result += "}\n";
  }
  return result;
}

std::string GenerateLongLine(int count) {
  if (count <= 0) {
    return std::string();
  }

  return "#" + std::string(count - 1, 'A');
}

}  // namespace

std::ostream& operator<<(std::ostream& os, ConfigErrorCode code) {
  switch (code) {
    case CONFIG_ERROR_NONE:
      return os << "OK";
    case CONFIG_ERROR_SECTION_NESTED_IN_GROUP:
      return os << "Section nested in group";
    case CONFIG_ERROR_SECTION_SYNTAX:
      return os << "ESection syntax error, expected '[section]'";
    case CONFIG_ERROR_EXPECTED_OPENING_CURLY_BRACE:
      return os << "Expected opening curly brace '{'";
    case CONFIG_ERROR_EXTRA_CURLY_BRACE:
      return os << "Extra curly brace";
    case CONFIG_ERROR_RELATION_SYNTAX:
      return os << "Relation syntax error, expected 'key = ...'";
    case CONFIG_ERROR_KEY_NOT_SUPPORTED:
      return os << "Key not supported";
    case CONFIG_ERROR_SECTION_NOT_SUPPORTED:
      return os << "Section not supported";
    case CONFIG_ERROR_KRB5_FAILED_TO_PARSE:
      return os << "KRB5 failed to parse";
    case CONFIG_ERROR_TOO_MANY_NESTED_GROUPS:
      return os << "Too many nested groups";
    case CONFIG_ERROR_LINE_TOO_LONG:
      return os << "Config line too long";
    default:
      NOTREACHED();
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, const ConfigErrorInfo& error_info) {
  if (error_info.code() == CONFIG_ERROR_NONE)
    return os << "[no error]";

  return os << error_info.code() << " at line " << error_info.line_index();
}

class ConfigParserTest : public ::testing::Test {
 protected:
  void ExpectNoError(const std::string& krb5conf) {
    ConfigErrorInfo error_info = config_parser_.Validate(krb5conf);

    EXPECT_TRUE(error_info.has_code()) << error_info;
    EXPECT_EQ(CONFIG_ERROR_NONE, error_info.code()) << error_info;
    EXPECT_FALSE(error_info.has_line_index()) << error_info;
  }

  void ExpectError(const std::string& krb5conf,
                   ConfigErrorCode code,
                   int line_index) {
    ConfigErrorInfo error_info = config_parser_.Validate(krb5conf);

    EXPECT_TRUE(error_info.has_code()) << error_info;
    EXPECT_EQ(code, error_info.code()) << error_info;
    EXPECT_TRUE(error_info.has_line_index()) << error_info;
    EXPECT_EQ(line_index, error_info.line_index()) << error_info;
  }

  void ExpectEncryptionTypes(
      const std::string& krb5conf,
      KerberosEncryptionTypes expected_encryption_types) {
    KerberosEncryptionTypes encryption_types;

    EXPECT_TRUE(config_parser_.GetEncryptionTypes(krb5conf, &encryption_types));
    EXPECT_EQ(expected_encryption_types, encryption_types);
  }

  ConfigParser config_parser_;
};

TEST_F(ConfigParserTest, ValidConfig) {
  ExpectNoError(kCompleteKrb5Conf);
}

TEST_F(ConfigParserTest, Empty) {
  ExpectNoError("");
  ExpectNoError("\n");
  ExpectNoError("\n\n\n");
  ExpectNoError("[libdefaults]");
  ExpectNoError("[libdefaults]\n");
  ExpectNoError("[libdefaults]\n\n\n");
}

TEST_F(ConfigParserTest, ModulesAndIncludesBlocked) {
  ExpectError("module MODULEPATH:RESIDUAL", CONFIG_ERROR_KEY_NOT_SUPPORTED, 0);
  ExpectError("include /path/to/file", CONFIG_ERROR_KEY_NOT_SUPPORTED, 0);
  ExpectError("includedir /path/to/files", CONFIG_ERROR_KEY_NOT_SUPPORTED, 0);

  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  includedir /path/to/files)";
  ExpectError(kKrb5Conf, CONFIG_ERROR_KEY_NOT_SUPPORTED, 2);
}

TEST_F(ConfigParserTest, UnsupportedLibdefaultsKey) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  stonkskew = 123)";
  ExpectError(kKrb5Conf, CONFIG_ERROR_KEY_NOT_SUPPORTED, 2);
}

TEST_F(ConfigParserTest, UnsupportedNestedLibdefaultsKey) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  A.EXAMPLE.COM = {
    stonkskew = 300
  })";
  ExpectError(kKrb5Conf, CONFIG_ERROR_KEY_NOT_SUPPORTED, 3);
}

TEST_F(ConfigParserTest, UnsupportedRealmKey) {
  constexpr char kKrb5Conf[] = R"(
[realms]
  BEISPIEL.FIR = {
    meister_svz = svz.beispiel.fir
  })";
  ExpectError(kKrb5Conf, CONFIG_ERROR_KEY_NOT_SUPPORTED, 3);
}

TEST_F(ConfigParserTest, RelationSyntaxErrorKeyWithoutEquals) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  kdc: kdc.example.com
)";
  ExpectError(kKrb5Conf, CONFIG_ERROR_RELATION_SYNTAX, 2);
}

TEST_F(ConfigParserTest, UnsupportedSection) {
  ExpectError("[appdefaults]", CONFIG_ERROR_SECTION_NOT_SUPPORTED, 0);
}

TEST_F(ConfigParserTest, SectionNestedInGroup) {
  constexpr char kKrb5Conf[] = R"(
[realms]
  EXAMPLE.COM = {
    [libdefaults]
  })";
  ExpectError(kKrb5Conf, CONFIG_ERROR_SECTION_NESTED_IN_GROUP, 3);
}

TEST_F(ConfigParserTest, MissingSectionBrackets) {
  ExpectError("[realms", CONFIG_ERROR_SECTION_SYNTAX, 0);
}

TEST_F(ConfigParserTest, SpacesBeforeSectionEndMarker) {
  // Note that the krb5 parser appears to accept spaces before the ']', but
  // it's a different section than without the spaces, so we reject it.
  ExpectError("[realms  ]", CONFIG_ERROR_SECTION_NOT_SUPPORTED, 0);
}

TEST_F(ConfigParserTest, ExtraStuffBeforeSectionBrackets) {
  ExpectError("extra [realms]", CONFIG_ERROR_RELATION_SYNTAX, 0);
}

TEST_F(ConfigParserTest, ExtraStuffAfterSectionBrackets) {
  ExpectError("[realms] extra", CONFIG_ERROR_SECTION_SYNTAX, 0);
}

TEST_F(ConfigParserTest, FinalMarkersAllowed) {
  ExpectNoError("[libdefaults]* \nclockskew*=9");
}

TEST_F(ConfigParserTest, FinalMarkersWithSpacesNotAllowed) {
  ExpectError("[libdefaults] *)", CONFIG_ERROR_SECTION_SYNTAX, 0);
  ExpectError("[libdefaults]\nclockskew *=9", CONFIG_ERROR_RELATION_SYNTAX, 1);
}

TEST_F(ConfigParserTest, RelationSyntaxError) {
  ExpectError("[libdefaults]\nclockskew", CONFIG_ERROR_RELATION_SYNTAX, 1);
  ExpectError("[libdefaults]\nclockskew ", CONFIG_ERROR_RELATION_SYNTAX, 1);
  ExpectError("[libdefaults]\nclockskew* ", CONFIG_ERROR_RELATION_SYNTAX, 1);
  ExpectError("[libdefaults]\n=clockskew*", CONFIG_ERROR_RELATION_SYNTAX, 1);
}

TEST_F(ConfigParserTest, TwoEqualSignsAllowed) {
  ExpectNoError("[libdefaults]\nclockskew=1=2");
}

TEST_F(ConfigParserTest, RelationSyntaxEdgeCases) {
  ExpectError("*", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError("*=", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError("=", CONFIG_ERROR_RELATION_SYNTAX, 0);

  ExpectError(" *", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError(" *=", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError(" =", CONFIG_ERROR_RELATION_SYNTAX, 0);

  ExpectError("* ", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError("*= ", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError("= ", CONFIG_ERROR_RELATION_SYNTAX, 0);

  ExpectError(" * ", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError(" *= ", CONFIG_ERROR_RELATION_SYNTAX, 0);
  ExpectError(" = ", CONFIG_ERROR_RELATION_SYNTAX, 0);

  ExpectError(" * = ", CONFIG_ERROR_RELATION_SYNTAX, 0);
}

TEST_F(ConfigParserTest, WhitespaceBeforeAndAfterSectionBrackets) {
  ExpectNoError("   [realms]   ");
}

TEST_F(ConfigParserTest, MissingOpeningCurlyBrace) {
  constexpr char kKrb5Conf[] = R"(
[realms]
  EXAMPLE.COM =

    kdc = kdc.example.com
  })";
  ExpectError(kKrb5Conf, CONFIG_ERROR_EXPECTED_OPENING_CURLY_BRACE, 3);
}

TEST_F(ConfigParserTest, ExtraCurlyBraceFound) {
  constexpr char kKrb5Conf[] = R"(
  [realms]
  EXAMPLE.COM =
  {
    kdc = kdc.example.com
  }
})";
  ExpectError(kKrb5Conf, CONFIG_ERROR_EXTRA_CURLY_BRACE, 6);
}

// Things that the fuzzer found.
TEST_F(ConfigParserTest, FuzzerRegressionTests) {
  // Code was looking at character after "include" to check if it's a space.
  ExpectError("include", CONFIG_ERROR_KEY_NOT_SUPPORTED, 0);

  // Code was accepting "[realms\0]" as a valid section. Embedded \0's should be
  // handled in a c_str() kind of way.
  std::string krb5confWithZero = "[realms\0]";
  krb5confWithZero[7] = 0;
  ExpectError(krb5confWithZero, CONFIG_ERROR_SECTION_SYNTAX, 0);

  // Code was allowing spaces in keys. Note that ConfigParser allows all keys
  // in the [domain_realm] section, but it should still check spaces!
  ExpectError("[domain_realm]\nkey x=", CONFIG_ERROR_RELATION_SYNTAX, 1);

  // \r should not be counted as newline character.
  ExpectError("[domain_realm]\rkey=", CONFIG_ERROR_SECTION_SYNTAX, 0);

  // Double == is always a relation, cannot be the start of a group.
  ExpectError("[capaths]\nkey==\n{", CONFIG_ERROR_RELATION_SYNTAX, 2);

  // Too many nested groups should lead to an error preventing stack overflow
  // in krb5 parser.
  ExpectNoError(GenerateNestedGroups(ConfigParser::kMaxGroupLevelDepth));
  ExpectError(GenerateNestedGroups(ConfigParser::kMaxGroupLevelDepth + 1),
              CONFIG_ERROR_TOO_MANY_NESTED_GROUPS,
              ConfigParser::kMaxGroupLevelDepth);

  // Config line too long should lead to an error.
  ExpectNoError(GenerateLongLine(ConfigParser::kKrb5MaxLineLength));
  ExpectError(GenerateLongLine(ConfigParser::kKrb5MaxLineLength + 1),
              CONFIG_ERROR_LINE_TOO_LONG, 0);

  // Leading/trailing whitespaces should be considered for the line size limit.
  ExpectError(std::string(" ") +
                  GenerateLongLine(ConfigParser::kKrb5MaxLineLength - 1) + " ",
              CONFIG_ERROR_LINE_TOO_LONG, 0);
}

// |GetEncryptionTypes| with a complete config to be parsed.
TEST_F(ConfigParserTest, GetEncryptionTypesCompleteConfig) {
  ExpectEncryptionTypes(kCompleteKrb5Conf, KerberosEncryptionTypes::kStrong);
}

// |GetEncryptionTypes| with all encryption types allowed.
TEST_F(ConfigParserTest, GetEncryptionTypesAll) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 arcfour-hmac-md5-exp
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 arcfour-hmac-md5-exp
  permitted_enctypes = aes256-cts-hmac-sha1-96 arcfour-hmac-md5-exp)";

  ExpectEncryptionTypes(kKrb5Conf, KerberosEncryptionTypes::kAll);
}

// |GetEncryptionTypes| with only strong encryption types allowed.
TEST_F(ConfigParserTest, GetEncryptionTypesStrong) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96)";

  ExpectEncryptionTypes(kKrb5Conf, KerberosEncryptionTypes::kStrong);
}

// |GetEncryptionTypes| with only legacy encryption types allowed.
TEST_F(ConfigParserTest, GetEncryptionTypesLegacy) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  default_tkt_enctypes = arcfour-hmac-md5-exp des3-cbc-raw
  default_tgs_enctypes = arcfour-hmac-md5-exp des3-cbc-raw
  permitted_enctypes = arcfour-hmac-md5-exp des3-cbc-raw)";

  ExpectEncryptionTypes(kKrb5Conf, KerberosEncryptionTypes::kLegacy);
}

// |GetEncryptionTypes| with enctypes fields missing.
TEST_F(ConfigParserTest, GetEncryptionTypesMissingFields) {
  // Empty config allows all encryption types.
  ExpectEncryptionTypes("", KerberosEncryptionTypes::kAll);

  constexpr char kKrb5Conf1[] = R"(
[libdefaults]
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96)";

  ExpectEncryptionTypes(kKrb5Conf1, KerberosEncryptionTypes::kAll);

  constexpr char kKrb5Conf2[] = R"(
[libdefaults]
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96)";

  ExpectEncryptionTypes(kKrb5Conf2, KerberosEncryptionTypes::kAll);

  constexpr char kKrb5Conf3[] = R"(
[libdefaults]
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes =aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96)";

  ExpectEncryptionTypes(kKrb5Conf3, KerberosEncryptionTypes::kAll);
}

// |GetEncryptionTypes| with |DEFAULT| enctypes assigned.
TEST_F(ConfigParserTest, GetEncryptionTypesDefaultValues) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  default_tkt_enctypes = DEFAULT
  default_tgs_enctypes = DEFAULT
  permitted_enctypes = DEFAULT)";

  // |DEFAULT| value allows all encryption types.
  ExpectEncryptionTypes(kKrb5Conf, KerberosEncryptionTypes::kAll);
}

// |GetEncryptionTypes| with comma separated encryption types list.
TEST_F(ConfigParserTest, GetEncryptionTypesCommaSeparated) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  default_tkt_enctypes = aes256-cts-hmac-sha1-96, arcfour-hmac-md5-exp
  default_tgs_enctypes = aes256-cts-hmac-sha1-96, arcfour-hmac-md5-exp
  permitted_enctypes = aes256-cts-hmac-sha1-96,arcfour-hmac-md5-exp)";

  ExpectEncryptionTypes(kKrb5Conf, KerberosEncryptionTypes::kAll);
}

// |GetEncryptionTypes| with invalid config.
TEST_F(ConfigParserTest, GetEncryptionTypesInvalidConfig) {
  constexpr char kKrb5Conf[] = R"(
[libdefaults]
  stonkskew = 123)";

  KerberosEncryptionTypes encryption_types;

  EXPECT_FALSE(config_parser_.GetEncryptionTypes(kKrb5Conf, &encryption_types));
  // |encryption_types| should've been set to the default value in our feature.
  EXPECT_EQ(KerberosEncryptionTypes::kStrong, encryption_types);
}

}  // namespace kerberos
