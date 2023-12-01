// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOBILE_OPERATOR_STORAGE_H_
#define SHILL_CELLULAR_MOBILE_OPERATOR_STORAGE_H_

#include <map>
#include <memory>
#include <string>

#include <base/files/file_util.h>
#include <base/no_destructor.h>
#include <gtest/gtest_prod.h>

#include "shill/mobile_operator_db/mobile_operator_db.pb.h"

namespace shill {

// This singleton class provides a function to parse databases with the format
// mobile_operator_db.proto and stores all the data in its instance. The main
// purpose of this class is to have a single instance of each database.

class MobileOperatorStorage {
 public:
  MobileOperatorStorage(const MobileOperatorStorage&) = delete;
  MobileOperatorStorage& operator=(const MobileOperatorStorage&) = delete;

  virtual ~MobileOperatorStorage();
  // Since this is a singleton, use MobileOperatorStorage::GetInstance()->Foo().
  static MobileOperatorStorage* GetInstance();

  // Parses the database and returns a pointer to the MobileOperatorDB object.
  // If the database has been already parsed in the past, the previously parsed
  // database will be returned. This class fully owns the returned value.
  const mobile_operator_db::MobileOperatorDB* GetDatabase(
      const base::FilePath& absolute_path);

 protected:
  MobileOperatorStorage();

 private:
  friend class base::NoDestructor<MobileOperatorStorage>;
  FRIEND_TEST(MobileOperatorMapperInitTest, FailedInitNoPath);
  // For testing only.
  void ClearDatabases();

  std::map<std::string,
           std::unique_ptr<const mobile_operator_db::MobileOperatorDB>>
      databases_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOBILE_OPERATOR_STORAGE_H_
