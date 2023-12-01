// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"testing"

	"chromiumos/scanning/utils"
)

// TestNoStoredJobSupportTest tests that NoStoredJobSupportTest functions
// correctly.
func TestNoStoredJobSupportTest(t *testing.T) {
	tests := []struct {
		storedJobRequestSupport utils.StoredJobRequestSupport
		result                  utils.TestResult
		failures                []utils.FailureType
	}{
		{
			storedJobRequestSupport: utils.StoredJobRequestSupport{
				MaxStoredJobRequests: 10,
				TimeoutInSeconds:     120,
				PINLength:            0,
				MaxJobNameLength:     0},
			result:   utils.Failed,
			failures: []utils.FailureType{utils.CriticalFailure},
		},
		{
			storedJobRequestSupport: utils.StoredJobRequestSupport{},
			result:                  utils.Passed,
			failures:                []utils.FailureType{},
		},
	}

	for _, tc := range tests {
		result, failures, err := NoStoredJobSupportTest(tc.storedJobRequestSupport)()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result != tc.result {
			t.Errorf("Result: expected %d, got %d", tc.result, result)
		}

		if len(failures) != len(tc.failures) {
			t.Errorf("Number of failures: expected %d, got %d", len(tc.failures), len(failures))
		}
		for i, failure := range failures {
			if failure.Type != tc.failures[i] {
				t.Errorf("FailureType: expected %d, got %d", tc.failures[i], failure.Type)
			}
		}
	}
}
