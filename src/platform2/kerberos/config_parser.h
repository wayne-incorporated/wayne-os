// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_CONFIG_PARSER_H_
#define KERBEROS_CONFIG_PARSER_H_

#include <string>

#include <base/containers/flat_set.h>

#include "kerberos/kerberos_metrics.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace kerberos {

// Parses the Kerberos configuration for either validation or encryption types
// retrieval. During Validation, verifies that only allowlisted configuration
// options are used. The Kerberos daemon does not allow all options for security
// reasons. Also performs basic syntax checks and returns more useful error
// information than "You screwed up your config, screw you!"
class ConfigParser {
 public:
  // Maximum depth of nested '{' in the config.
  static constexpr int kMaxGroupLevelDepth = 1000;

  // Maximum length of each line in the config. This value matches the buffer
  // size used in the krb5 library, minus one, to account for the null
  // character ('\0').
  // https://github.com/krb5/krb5/blob/krb5-1.20.1-final/src/util/profile/prof_parse.c#L328
  static constexpr size_t kKrb5MaxLineLength = 2047;

  ConfigParser();
  ConfigParser(const ConfigParser&) = delete;
  ConfigParser& operator=(const ConfigParser&) = delete;

  // Checks the Kerberos configuration |krb5conf|. If the config cannot be
  // parsed or a non-allowlisted option is used, returns a message with proper
  // error code and the 0-based line index where the error occurred. If the
  // config was validated successfully, returns a message with code set to
  // |CONFIG_ERROR_NONE|.
  ConfigErrorInfo Validate(const std::string& krb5conf) const;

  // Retrieves the encryption types allowed in |krb5conf| and returns whether
  // the operation was successful or not. It should fail only if the config is
  // invalid. Encryption types can be specified in three different fields. If
  // any of these fields is not specified, the default value for the
  // corresponding field in krb5.conf ('all') will be used. The union of the
  // three provided lists will be taken into consideration and mapped into one
  // of the following comprehensive disjoint groups:
  // * 'All': contains at least one AES type and at least one type from another
  // encryption family
  // * 'Strong': contains only AES encryption types (at least one of them)
  // * 'Legacy': contains no AES encryption types
  bool GetEncryptionTypes(const std::string& krb5conf,
                          KerberosEncryptionTypes* encryption_types) const;

 private:
  // Internal method with common parsing features, used by |Validate(krb5conf)|
  // and |GetEncryptionTypes(krb5conf)|. Returns both the ConfigErrorInfo and
  // KerberosEncryptionTypes for the given config. The last value is meaningful
  // only if the config is valid.
  ConfigErrorInfo ParseConfig(const std::string& krb5conf,
                              KerberosEncryptionTypes* encryption_types) const;

  bool IsKeySupported(const std::string& key,
                      const std::string& section,
                      int group_level) const;

  using StringSet = base::flat_set<std::string>;
  const StringSet libdefaults_allowlist_;
  const StringSet realms_allowlist_;
  const StringSet section_allowlist_;
  const StringSet enctypes_fields_;
  const StringSet weak_enctypes_;
  const StringSet strong_enctypes_;
};

}  // namespace kerberos

#endif  // KERBEROS_CONFIG_PARSER_H_
