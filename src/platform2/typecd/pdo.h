// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_PDO_H_
#define TYPECD_PDO_H_

#include <memory>

#include <base/files/file_path.h>
#include <base/logging.h>

namespace typecd {

// This class represents a Power Delivery Object (PDO) advertised by a
// Peripheral. Each PDO represents a power capability of the connected
// peripheral (either as a source or as a sink). A Peripherals source and sink
// capabilities are composed of sets of PDOs.
class Pdo {
 public:
  // List of the various types of PDOs exposed via sysfs.
  enum class Type {
    kNone = 0,
    kFixedSupply = 1,
    kVariableSupply = 2,
    kBattery = 3,
    kPPS = 4,
    kMaxValue = kPPS,
  };

  // Factory function which returns a Pdo object or nullptr on error.
  // It does some validation to make sure the directory holds valid
  // PDO information.
  static std::unique_ptr<Pdo> MakePdo(const base::FilePath& syspath);
  explicit Pdo(const base::FilePath& syspath, Type type, int index);

  Type GetType() { return type_; }
  int GetIndex() { return index_; }

  Pdo(const Pdo&) = delete;
  Pdo& operator=(const Pdo&) = delete;

 private:
  // Sysfs path used to access power delivery directory.
  base::FilePath syspath_;
  Type type_;
  int index_;
};

}  // namespace typecd

#endif  // TYPECD_PDO_H_
