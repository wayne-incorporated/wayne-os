// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

type TestArgs = {
  args: any;
  text?: string;
  test?: any;
  debug?: any;
}

/**
 * Test wrapper around for the expect and async test functions.
 * @param tests Array of test arguments.
 * @param expectFun Comparison function provided to the test.
 */
export function tester(
    tests: TestArgs[], expectFun: (args: any, test?: any) => void) {
  for (const [index, test] of tests.entries()) {
    // Fallback text if it is not available.
    let text = test.text;
    if (!text) {
      text = index + ': ' + String(test.args);
    }
    it(text, () => {
      try {
        expectFun(test.args, test.test);
      } catch (error) {
        console.error('ERROR', test);
        console.error(expectFun);
      }
    });
  }
}
