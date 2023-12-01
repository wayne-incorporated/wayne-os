// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/config_parser.h"

#include <vector>

#include <base/containers/contains.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

namespace kerberos {
namespace {

// See
// https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html
// for a description of the krb5.conf format.

// Directives that are not relations (i.e. key=value). All blocklisted.
const char* const kDirectives[] = {"module", "include", "includedir"};

// Allowlisted configuration keys in the [libdefaults] section.
const char* const kLibDefaultsAllowlist[] = {
    "canonicalize",
    "clockskew",
    "default_tgs_enctypes",
    "default_tkt_enctypes",
    "dns_canonicalize_hostname",
    "dns_lookup_kdc",
    "extra_addresses",
    "forwardable",
    "ignore_acceptor_hostname",
    "kdc_default_options",
    "kdc_timesync",
    "noaddresses",
    "permitted_enctypes",
    "preferred_preauth_types",
    "proxiable",
    "rdns",
    "renew_lifetime",
    "ticket_lifetime",
    "udp_preference_limit",
};

// Allowlisted configuration keys in the [realms] section.
const char* const kRealmsAllowlist[] = {
    "admin_server",   "auth_to_local", "kdc",
    "kpasswd_server", "master_kdc",  // nocheck
};

// Allowlisted sections. Any key in "domain_realm" and "capaths" is accepted.
constexpr char kSectionLibdefaults[] = "libdefaults";
constexpr char kSectionRealms[] = "realms";
constexpr char kSectionDomainRealm[] = "domain_realm";
constexpr char kSectionCapaths[] = "capaths";

const char* const kSectionAllowlist[] = {kSectionLibdefaults, kSectionRealms,
                                         kSectionDomainRealm, kSectionCapaths};

// List of encryption types fields allowed inside [libdefaults] section.
const char* const kEnctypesFields[] = {
    "default_tgs_enctypes",
    "default_tkt_enctypes",
    "permitted_enctypes",
};

// List of weak encryption types. |DEFAULT| value is also listed because it
// includes both weak and strong types.
const char* const kWeakEnctypes[] = {
    "DEFAULT",
    "des",
    "des3",
    "rc4",
    "des-cbc-crc",
    "des-cbc-md4",
    "des-cbc-md5",
    "des-cbc-raw",
    "des-hmac-sha1",
    "des3-cbc-raw",
    "des3-cbc-sha1",
    "des3-hmac-sha1",
    "des3-cbc-sha1-kd",
    "arcfour-hmac",
    "rc4-hmac",
    "arcfour-hmac-md5",
    "arcfour-hmac-exp",
    "rc4-hmac-exp",
    "arcfour-hmac-md5-exp",
};

// List of strong encryption types. |DEFAULT| value is also listed because it
// includes both weak and strong types.
const char* const kStrongEnctypes[] = {
    "DEFAULT",    "aes",     "aes256-cts-hmac-sha1-96",
    "aes256-cts", "AES-256", "aes128-cts-hmac-sha1-96",
    "aes128-cts", "AES-128",
};

ConfigErrorInfo MakeErrorInfo(ConfigErrorCode code, int line_index) {
  ConfigErrorInfo error_info;
  error_info.set_code(code);
  error_info.set_line_index(line_index);
  return error_info;
}

}  // namespace

ConfigParser::ConfigParser()
    : libdefaults_allowlist_(std::begin(kLibDefaultsAllowlist),
                             std::end(kLibDefaultsAllowlist)),
      realms_allowlist_(std::begin(kRealmsAllowlist),
                        std::end(kRealmsAllowlist)),
      section_allowlist_(std::begin(kSectionAllowlist),
                         std::end(kSectionAllowlist)),
      enctypes_fields_(std::begin(kEnctypesFields), std::end(kEnctypesFields)),
      weak_enctypes_(std::begin(kWeakEnctypes), std::end(kWeakEnctypes)),
      strong_enctypes_(std::begin(kStrongEnctypes), std::end(kStrongEnctypes)) {
}

ConfigErrorInfo ConfigParser::Validate(const std::string& krb5conf) const {
  KerberosEncryptionTypes encryption_types;
  return ParseConfig(krb5conf, &encryption_types);
}

bool ConfigParser::GetEncryptionTypes(
    const std::string& krb5conf,
    KerberosEncryptionTypes* encryption_types) const {
  ConfigErrorInfo error_info = ParseConfig(krb5conf, encryption_types);
  return error_info.code() == CONFIG_ERROR_NONE;
}

// Validates the config and gets encryption types from it. Finds the enctypes
// fields and maps the union of the enctypes into one of the buckets of
// interest: 'All', 'Strong' or 'Legacy'. If an enctypes field is missing, the
// default value for this field ('All') will be used.
ConfigErrorInfo ConfigParser::ParseConfig(
    const std::string& krb5conf,
    KerberosEncryptionTypes* encryption_types) const {
  // Variables used to keep track of encryption fields and types on |krc5conf|.
  StringSet listed_enctypes_fields;
  bool has_weak_enctype = false;
  bool has_strong_enctype = false;

  // Initializes |encryption_types| with the default value in our feature. It
  // will be replaced at the end of this method, if |krb5conf| is valid.
  *encryption_types = KerberosEncryptionTypes::kStrong;

  // Keep whitespaces to preserve the original line size. Keep empty lines,
  // they're necessary to get the line numbers right. Note: The MIT krb5
  // parser does not count \r as newline.
  const std::vector<std::string> lines = base::SplitString(
      krb5conf, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  // Level of nested curly braces {}.
  int group_level = 0;

  // Opening curly braces '{' can be on the same line and on the next line. This
  // is set to true if a '{' is expected on the next line.
  bool expect_opening_curly_brace = false;

  // Current [section].
  std::string current_section;

  for (size_t line_index = 0; line_index < lines.size(); ++line_index) {
    // Convert to c_str() and back to get rid of embedded \0's.
    std::string line = lines.at(line_index).c_str();

    if (line.size() > kKrb5MaxLineLength) {
      return MakeErrorInfo(CONFIG_ERROR_LINE_TOO_LONG, line_index);
    }

    // After validating the original line length, we want to trim whitespaces.
    base::TrimWhitespaceASCII(line, base::TRIM_ALL, &line);

    // Are we expecting a '{' to open a { group }?
    if (expect_opening_curly_brace) {
      if (line.empty() || line.at(0) != '{') {
        return MakeErrorInfo(CONFIG_ERROR_EXPECTED_OPENING_CURLY_BRACE,
                             line_index);
      }
      group_level++;
      // If too nested config, exit here to prevent krb5 stack overflow.
      if (group_level > kMaxGroupLevelDepth)
        return MakeErrorInfo(CONFIG_ERROR_TOO_MANY_NESTED_GROUPS, line_index);
      expect_opening_curly_brace = false;
      continue;
    }

    // Skip empty lines.
    if (line.empty())
      continue;

    // Skip comments.
    if (line.at(0) == ';' || line.at(0) == '#')
      continue;

    // Bail on any |kDirectives|.
    for (const char* directive : kDirectives) {
      const int len = strlen(directive);
      const int line_len = static_cast<int>(line.size());
      if (strncmp(line.c_str(), directive, len) == 0 &&
          (len >= line_len || isspace(line.at(len)))) {
        return MakeErrorInfo(CONFIG_ERROR_KEY_NOT_SUPPORTED, line_index);
      }
    }

    // Check for '}' to close a { group }.
    if (line.at(0) == '}') {
      if (group_level == 0)
        return MakeErrorInfo(CONFIG_ERROR_EXTRA_CURLY_BRACE, line_index);
      group_level--;
      continue;
    }

    // Check for new [section].
    if (line.at(0) == '[') {
      // Bail if section is within a { group }.
      if (group_level > 0)
        return MakeErrorInfo(CONFIG_ERROR_SECTION_NESTED_IN_GROUP, line_index);

      // Bail if closing bracket is missing or if there's more stuff after the
      // closing bracket (the final marker '*' is fine).
      std::vector<std::string> parts = base::SplitString(
          line, "]", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
      if (parts.size() != 2 || !(parts.at(1).empty() || parts.at(1) == "*"))
        return MakeErrorInfo(CONFIG_ERROR_SECTION_SYNTAX, line_index);

      current_section = parts.at(0).substr(1);

      // Bail if the section is not supported, e.g. [appdefaults].
      if (current_section.empty() ||
          !base::Contains(section_allowlist_, current_section)) {
        return MakeErrorInfo(CONFIG_ERROR_SECTION_NOT_SUPPORTED, line_index);
      }
      continue;
    }

    // Check for "key = value" or "key = {".
    std::vector<std::string> parts = base::SplitString(
        line, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

    // Remove final marker.
    std::string& key = parts.at(0);
    if (key.back() == '*')
      key.pop_back();

    // No space allowed in the key.
    if (std::find_if(key.begin(), key.end(), isspace) != key.end())
      return MakeErrorInfo(CONFIG_ERROR_RELATION_SYNTAX, line_index);

    // Final marker must come immediately after key.
    if (key.empty() || isspace(key.back()))
      return MakeErrorInfo(CONFIG_ERROR_RELATION_SYNTAX, line_index);

    // Is there at least one '=' sign?
    if (parts.size() < 2)
      return MakeErrorInfo(CONFIG_ERROR_RELATION_SYNTAX, line_index);

    const std::string& value = parts.at(1);
    if (parts.size() == 2) {
      // Check for a '{' to start a group. The '{' could also be on the next
      // line. If there's anything except whitespace after '{', it counts as
      // value, not as a group.
      // Note: If there is more than one '=', it cannot be the start of a group,
      // e.g. key==\n{.
      if (value.empty()) {
        expect_opening_curly_brace = true;
        continue;
      }
      if (value == "{") {
        group_level++;
        // If too nested config, exit here to prevent krb5 stack overflow.
        if (group_level > kMaxGroupLevelDepth)
          return MakeErrorInfo(CONFIG_ERROR_TOO_MANY_NESTED_GROUPS, line_index);
        continue;
      }
    }

    // Check whether we support the key.
    if (!IsKeySupported(key, current_section, group_level))
      return MakeErrorInfo(CONFIG_ERROR_KEY_NOT_SUPPORTED, line_index);

    // If |key| is a enctypes field in the [libdefaults] section.
    if (current_section == kSectionLibdefaults && group_level <= 1 &&
        base::Contains(enctypes_fields_, key)) {
      listed_enctypes_fields.insert(key);

      // Note: encryption types can be delimited by comma or whitespace.
      const std::vector<std::string> enctypes = base::SplitString(
          value, ", ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

      for (const std::string& type : enctypes) {
        has_weak_enctype |= base::Contains(weak_enctypes_, type);
        has_strong_enctype |= base::Contains(strong_enctypes_, type);
      }
    }
  }

  // Note: if an enctypes field is missing, the default value is 'All'.
  if (listed_enctypes_fields.size() < enctypes_fields_.size() ||
      (has_weak_enctype && has_strong_enctype)) {
    *encryption_types = KerberosEncryptionTypes::kAll;
  } else if (has_strong_enctype) {
    *encryption_types = KerberosEncryptionTypes::kStrong;
  } else {
    *encryption_types = KerberosEncryptionTypes::kLegacy;
  }

  ConfigErrorInfo error_info;
  error_info.set_code(CONFIG_ERROR_NONE);
  return error_info;
}

bool ConfigParser::IsKeySupported(const std::string& key,
                                  const std::string& section,
                                  int group_level) const {
  // Bail on anything outside of a section.
  if (section.empty())
    return false;

  // Enforce only allowlisted libdefaults keys on the root and realm levels:
  // [libdefaults]
  //   clockskew = 300
  //   EXAMPLE.COM = {
  //     clockskew = 500
  //   }
  if (section == kSectionLibdefaults && group_level <= 1) {
    return base::Contains(libdefaults_allowlist_, key);
  }

  // Enforce only allowlisted realm keys on the root and realm levels:
  // [realms]
  //   kdc = kerberos1.example.com
  //   EXAMPLE.COM = {
  //      kdc = kerberos2.example.com
  //   }
  // Not sure if they can actually be at the root level, but just in case...
  if (section == kSectionRealms && group_level <= 1)
    return base::Contains(realms_allowlist_, key);

  // Anything else is fine (all keys of other supported sections).
  return true;
}

}  // namespace kerberos
