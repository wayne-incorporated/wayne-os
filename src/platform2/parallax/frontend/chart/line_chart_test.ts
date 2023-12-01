// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {LineChart} from '@parallax/chart/line_chart';
import {tester} from '@parallax/common/test';

describe('LineChart', () => {
  const VALID = [
    {
      text: 'Normal Array',
      args: {
        meta: {rowMeta: [{name: '1'}, {name: '2'}, {name: '3'}]},
        matrix: [[1, 2, 3, 4, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4, 5]],
      },
    },
    {
      text: 'Empty Array',
      args: {
        meta: {rowMeta: [{name: '1'}, {name: '2'}, {name: '3'}]},
        matrix: [[], [], []],
      },
    },
  ];

  const ERROR = [
    {
      text: 'Missing row',
      args: {
        meta: {rowMeta: [{name: '1'}, {name: '2'}, {name: '3'}]},
        matrix: [[1, 2, 3, 4, 5], [1, 2, 3, 4, 5]],
      },
    },
    {
      text: 'Missing cell',
      args: {
        meta: {rowMeta: [{name: '1'}, {name: '2'}, {name: '3'}]},
        matrix: [[1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 4, 5]],
      },
    },
    {
      text: '1D-Array',
      args: {
        meta: {rowMeta: [{name: '1'}, {name: '2'}, {name: '3'}]},
        matrix: [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5],
      },
    },
  ];

  describe('Constructor Valid', () => {
    tester(VALID, (x: any) => {
      expect(new LineChart(x.meta, x.matrix)).toBeDefined();
    });
  });

  describe('Constructor Error', () => {
    tester(ERROR, (x: any) => {
      expect(() => {
        new LineChart(x.meta, x.matrix);
      }).toThrowError();
    });
  });
});
