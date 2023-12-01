// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "authpolicy/anonymizer.h"

namespace {

constexpr char kLog[] =
    "Starting fake search for user name USER_NAME\n"
    "Found 1 entry:\n"
    "  userNameKey  :   USER_NAME  ";

constexpr char kMultiLog[] =
    "Starting fake search for key KEY_WITH_MULTIPLE_MATCHES\n"
    "Found 2 entries:\n"
    "userNameKey: USER_NAME\n"
    "userNameKey: DIFFERENT_NAME\n";

constexpr char kDifferentCasesLog[] =
    "Starting fake search for key KEY_WITH_MULTIPLE_MATCHES\n"
    "Found 2 entries:\n"
    "userNameKey: USER_NAME\n"
    "userNameKey: user_name\n";

constexpr char kDifferentLogWithSameUserName[] =
    "Different string containing USER_NAME\n";

constexpr char kLogWithDifferentUserName[] = "userNameKey: DIFFERENT_NAME\n";

constexpr char kUserNameKey[] = "userNameKey";
constexpr char kUserName[] = "USER_NAME";
constexpr char kUserNameLowerCase[] = "user_name";
constexpr char kReplacement[] = "REPLACEMENT";
constexpr char kDifferentUserName[] = "DIFFERENT_NAME";

// Counts the number of occurrances of |substr| in |str|.
int CountOccurrances(const std::string& str, const std::string substr) {
  int count = 0;
  size_t pos = str.find(substr);
  while (pos != std::string::npos) {
    count++;
    pos = str.find(substr, pos + substr.size());
  }
  return count;
}

}  // namespace

namespace authpolicy {

class AnonymizerTest : public ::testing::Test {
 public:
  AnonymizerTest() {}
  AnonymizerTest(const AnonymizerTest&) = delete;
  AnonymizerTest& operator=(const AnonymizerTest&) = delete;
  ~AnonymizerTest() override {}

 protected:
  Anonymizer anonymizer_;
};

// Anonymizer does not change string if no replacements are set.
TEST_F(AnonymizerTest, NoChangeIfEmpty) {
  std::string anonymized_log = anonymizer_.Process(kLog);
  EXPECT_EQ(kLog, anonymized_log);
}

// Anonymizer replaces strings.
TEST_F(AnonymizerTest, ReplaceStrings) {
  EXPECT_NE(nullptr, strstr(kLog, kUserName));
  EXPECT_EQ(nullptr, strstr(kLog, kReplacement));

  anonymizer_.SetReplacement(kUserName, kReplacement);
  std::string anonymized_log = anonymizer_.Process(kLog);

  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_NE(std::string::npos, anonymized_log.find(kReplacement));
}

// SetReplacementAllCases replaces upper- and lower-case strings.
TEST_F(AnonymizerTest, ReplaceStringsAllCases) {
  EXPECT_NE(nullptr, strstr(kDifferentCasesLog, kUserName));
  EXPECT_NE(nullptr, strstr(kDifferentCasesLog, kUserNameLowerCase));
  EXPECT_EQ(nullptr, strstr(kDifferentCasesLog, kReplacement));

  anonymizer_.SetReplacementAllCases(kUserName, kReplacement);
  std::string anonymized_log = anonymizer_.Process(kDifferentCasesLog);

  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserNameLowerCase));
  EXPECT_NE(std::string::npos, anonymized_log.find(kReplacement));
}

// Anonymizer finds and replaces strings from search results.
TEST_F(AnonymizerTest, FindAndReplaceSearchValues) {
  anonymizer_.ReplaceSearchArg(kUserNameKey, kReplacement);
  std::string anonymized_log = anonymizer_.Process(kLog);

  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_NE(std::string::npos, anonymized_log.find(kReplacement));

  // Even after resetting search arg replacements, the replacement kUserName ->
  // kReplacement should still hold.
  anonymizer_.ResetSearchArgReplacements();
  anonymized_log = anonymizer_.Process(kDifferentLogWithSameUserName);
  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_NE(std::string::npos, anonymized_log.find(kReplacement));

  // However, the anonymizer should not pick up a different search result
  // anymore.
  anonymized_log = anonymizer_.Process(kLogWithDifferentUserName);
  EXPECT_NE(std::string::npos, anonymized_log.find(kDifferentUserName));
  EXPECT_EQ(std::string::npos, anonymized_log.find(kReplacement));
}

// Search regex works.
TEST_F(AnonymizerTest, SearchRegEx) {
  anonymizer_.ReplaceSearchArg("key", "anonymized", "Name='(\\w+)'");
  std::string anonymized_log = anonymizer_.Process("key:Name='sensitive'");
  EXPECT_EQ("key:Name='anonymized'", anonymized_log);
}

// Anonymizer finds multiple search results.
TEST_F(AnonymizerTest, FindMultipleSearchValues) {
  EXPECT_NE(nullptr, strstr(kMultiLog, kUserName));
  EXPECT_NE(nullptr, strstr(kMultiLog, kDifferentUserName));
  EXPECT_EQ(nullptr, strstr(kMultiLog, kReplacement));

  anonymizer_.ReplaceSearchArg(kUserNameKey, kReplacement);
  std::string anonymized_log = anonymizer_.Process(kMultiLog);

  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_EQ(std::string::npos, anonymized_log.find(kDifferentUserName));
  EXPECT_EQ(2, CountOccurrances(anonymized_log, kReplacement));
}

// Anonymizer replaces ABC_KEY, XYZ_KEY and KEY_123 before KEY. Note that
// ABC_KEY < KEY < KEY_123 < XYZ_KEY.
TEST_F(AnonymizerTest, DoesNotReplaceShorterStringsFirst) {
  anonymizer_.SetReplacement("ABC_KEY", "ABC_REP");
  anonymizer_.SetReplacement("XYZ_KEY", "XYZ_REP");
  anonymizer_.SetReplacement("KEY", "KEY_REP");
  anonymizer_.SetReplacement("KEY_123", "123_REP");
  constexpr char str[] = "ABC_KEY XYZ_KEY KEY KEY_123";
  std::string anonymized_str = anonymizer_.Process(str);
  EXPECT_EQ("ABC_REP XYZ_REP KEY_REP 123_REP", anonymized_str);
}

// Disabling the anonymizer causes Process() to return the original string.
TEST_F(AnonymizerTest, Disable) {
  anonymizer_.ReplaceSearchArg(kUserNameKey, kReplacement);
  anonymizer_.set_disabled(true);
  std::string anonymized_log = anonymizer_.Process(kLog);
  EXPECT_EQ(anonymized_log, kLog);

  // Once reenabled, anonymizer should anonymize again and even remember the
  // replacement found before.
  anonymizer_.set_disabled(false);
  anonymizer_.ResetSearchArgReplacements();
  anonymized_log = anonymizer_.Process(kDifferentLogWithSameUserName);
  EXPECT_EQ(std::string::npos, anonymized_log.find(kUserName));
  EXPECT_NE(std::string::npos, anonymized_log.find(kReplacement));
}

}  // namespace authpolicy
