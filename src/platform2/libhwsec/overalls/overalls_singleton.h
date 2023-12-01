// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_OVERALLS_OVERALLS_SINGLETON_H_
#define LIBHWSEC_OVERALLS_OVERALLS_SINGLETON_H_

#include "libhwsec/hwsec_export.h"
#include "libhwsec/overalls/overalls.h"

namespace hwsec {
namespace overalls {

// This class manages the singleton of |Overalls| instance; it is also
// responsible for creating a normal |Overalls| (i.e. an |Overalls| instance
// that directly calls |trousers| APIs) as the default singleton instance.
class HWSEC_EXPORT OverallsSingleton {
 public:
  // Returns the singleton of the |Overalls|. See the private field doc for more
  // information.
  static Overalls* GetInstance();

  // A helper function to set the instance so we can replace the singleton when
  // necessary. Returns the |Overalls| instance stored in this class so the
  // state restoration is possible.
  static Overalls* SetInstance(Overalls* ins);

 private:
  // A singleton instance of |Overalls|. By default, it is a normal class (i.e.,
  // calling |trousers|).
  static Overalls* overalls_;
};

}  // namespace overalls
}  // namespace hwsec

#endif  // LIBHWSEC_OVERALLS_OVERALLS_SINGLETON_H_
