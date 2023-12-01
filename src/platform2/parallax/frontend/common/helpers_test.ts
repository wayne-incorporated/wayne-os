// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {iterableArray, iterableMap} from '@parallax/common/helpers';

describe('iteration', () => {
  const VALID_ARRAY = [
    JSON.parse('["zero", 1, "two", 3]'),
    ['four', 5, 'six'],
    [1, 2, 3],
    new Set([1, 2, 3]),
  ];

  const VALID_MAPS = [
    JSON.parse('{"1":2,"3":4}'),
    {5: 6, 7: 8},
  ];

  const ERROR_COMMON = [
    parseInt,
    'test',
    undefined,
    1,
    NaN,
  ];

  describe('iterableArray', () => {
    it('Input Valid', () => {
      for (const args of VALID_ARRAY) {
        expect(iterableArray(args)).toBeDefined();
      }
    });


    it('Input Error', () => {
      const invalid = ERROR_COMMON.concat(VALID_MAPS);
      for (const args of invalid) {
        expect(() => {
          iterableArray(args);
        }).toThrowError();
      }
    });
  });

  describe('iterableMap', () => {
    it('Input Valid', () => {
      for (const args of VALID_MAPS) {
        expect(iterableMap(args)).toBeDefined();
      }
    });


    it('Input Error', () => {
      const ERROR_INPUT = ERROR_COMMON.concat(VALID_ARRAY);
      for (const [i, args] of ERROR_INPUT.entries()) {
        expect(() => {
          iterableMap(args);
        }).toThrowError();
      }
    });
  });
});
