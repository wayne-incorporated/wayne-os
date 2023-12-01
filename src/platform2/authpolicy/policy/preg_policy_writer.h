// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_PREG_POLICY_WRITER_H_
#define AUTHPOLICY_POLICY_PREG_POLICY_WRITER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "authpolicy/policy/user_policy_encoder.h"

namespace policy {

// Helper class to write valid registry.pol ("PREG") files with the specified
// policy values. Useful to test preg parsing and encoding for in unit tests.
// See https://msdn.microsoft.com/en-us/library/aa374407(v=vs.85).aspx for a
// description of the file format.
// TAKE NOTE: When writing strings, this writer only supports US-ASCII - other
// codepoints are not properly converted to UTF16-LE when written to file.
class PRegPolicyWriter {
 public:
  // Creates a new writer using |mandatory_key| as registry key for mandatory
  // policies and |recommended_key| for recommended policies.
  PRegPolicyWriter(const std::string& mandatory_key,
                   const std::string& recommended_key);

  // Creates a new writer with empty keys. Must set the keys manually before
  // Append* can be called.
  PRegPolicyWriter();

  ~PRegPolicyWriter();

  // Sets the registry key used for mandatory policies. Subsequent Append* calls
  // will use this key.
  void SetMandatoryKey(const std::string& mandatory_key);

  // Sets the registry key used for recommended policies. Subsequent Append*
  // calls will use this key.
  void SetRecommendedKey(const std::string& recommended_key);

  // Sets registry keys suitable for writing user and device policy. Subsequent
  // Append* calls will use these keys.
  void SetKeysForUserDevicePolicy();

  // Sets registry keys suitable for writing extension policy for an extension
  // with the given 32-byte |extension_id|. Subsequent Append* calls will use
  // these keys.
  void SetKeysForExtensionPolicy(const std::string& extension_id);

  // Appends a boolean policy value. Must set keys beforehand.
  void AppendBoolean(const char* policy_name,
                     bool value,
                     PolicyLevel level = POLICY_LEVEL_MANDATORY);

  // Appends an integer policy value. Must set keys beforehand.
  void AppendInteger(const char* policy_name,
                     uint32_t value,
                     PolicyLevel level = POLICY_LEVEL_MANDATORY);

  // Appends a string policy value. Must set keys beforehand.
  void AppendString(const char* policy_name,
                    const std::string& value,
                    PolicyLevel level = POLICY_LEVEL_MANDATORY);

  // Appends a multi-line string policy value. Must set keys beforehand.
  void AppendMultiString(const char* policy_name,
                         const std::vector<std::string>& values,
                         PolicyLevel level = POLICY_LEVEL_MANDATORY);

  // Appends a string list policy value. Must set keys beforehand.
  void AppendStringList(const char* policy_name,
                        const std::vector<std::string>& values,
                        PolicyLevel level = POLICY_LEVEL_MANDATORY);

  // Writes the policy data to a file. Returns true on success.
  bool WriteToFile(const base::FilePath& path);

 private:
  // Starts a policy entry. Entries have the shape '[key;value;type;size;data]'.
  // This method writes '[key;value;type;size;'.
  void StartEntry(const std::string& key_name,
                  const std::string& value_name,
                  uint32_t data_type,
                  uint32_t data_size);

  // Ends a policy entry (writes ']'). The caller has to fill in the data
  // between StartEntry() and EndEntry().
  void EndEntry();

  // Appends a NULL terminated string to the internal buffer. Note that all
  // strings are written as char16s.
  void AppendNullTerminatedString(const std::string& str);

  // Appends an unsigned integer to the internal buffer.
  void AppendUnsignedInt(uint32_t value);

  // Appends a char16 to the internal buffer.
  void AppendChar16(char16_t ch);

  // Returns the registry key that belongs to the given |level|.
  const std::string& GetKey(PolicyLevel level);

  std::string mandatory_key_;
  std::string recommended_key_;
  std::string buffer_;

  // Safety check that every StartEntry() is followed by EndEntry().
  bool entry_started_ = false;
};

// Shortcut to create a writer and set keys for writing user and device policy.
class PRegUserDevicePolicyWriter : public PRegPolicyWriter {
 public:
  PRegUserDevicePolicyWriter();
};

// Shortcut to create a writer and set keys for writing extension policy.
class PRegExtensionPolicyWriter : public PRegPolicyWriter {
 public:
  explicit PRegExtensionPolicyWriter(const std::string& extension_id);
};

}  // namespace policy

#endif  // AUTHPOLICY_POLICY_PREG_POLICY_WRITER_H_
