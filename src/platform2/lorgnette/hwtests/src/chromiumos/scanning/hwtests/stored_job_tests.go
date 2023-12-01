// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"github.com/google/go-cmp/cmp"

	"chromiumos/scanning/utils"
)

// NoStoredJobSupportTest passes if `storedJobRequestSupport` is empty.
// Otherwise, the test returns a critical failure.
func NoStoredJobSupportTest(storedJobRequestSupport utils.StoredJobRequestSupport) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if cmp.Equal(storedJobRequestSupport, utils.StoredJobRequestSupport{}) {
			result = utils.Passed
		} else {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: "Scanner advertises stored job support."})
			result = utils.Failed
		}
		return
	}
}
