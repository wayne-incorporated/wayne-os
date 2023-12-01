// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCKABLE_H_
#define SHILL_MOCKABLE_H_

// The mockable keyword is used for methods that should not be overridden by
// regular children but still should be mocked.
//
// Note that this keyword should *not* be used as an excuse for abusing
// mocks. Our tests should be verifying behavior, not implementation, and the
// abuse of mocks is an enabler of the latter. Ideally our usage of mocks would
// be constrained to the point that this keyword is not necessary at all. For
// the interim, however, this keyword provides clarity in a codebase that
// already abuses mocks.
#ifndef TEST_BUILD
#define mockable
#else
#define mockable virtual
#endif  // TEST_BUILD

#endif  // SHILL_MOCKABLE_H_
