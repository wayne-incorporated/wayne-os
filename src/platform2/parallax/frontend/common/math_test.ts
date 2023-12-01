// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {Matrix} from '@parallax/common/math';
import {tester} from '@parallax/common/test';

describe('Matrix', () => {
  const VALID = [
    {
      text: '3x3',
      args: [[1, 2, 3], [4, 5, 6], [7, 8, 9]],
      test: {
        rows: 3,
        cols: 3,
      },
    },
    {
      text: '3x5',
      args: [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10], [11, 12, 13, 14, 15]],
      test: {
        rows: 3,
        cols: 5,
      },
    },
  ];

  const ERROR = [
    {
      text: 'Missing cell',
      args: [[1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 4, 5]],
    },
    {text: '1-D', args: [1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5]},
  ];

  describe('Constructor Valid', () => {
    tester(VALID, (x: any) => {
      expect(new Matrix(x)).toBeDefined();
    });
  });

  describe('Constructor Error', () => {
    tester(ERROR, (x: any) => {
      expect(() => {
        new Matrix(x);
      }).toThrowError();
    });
  });

  describe('Addressing', () => {
    tester(VALID, (x: any, y: any) => {
      const matrix = new Matrix(x);
      expect(y.rows).toBe(x.length);
      expect(y.cols).toBe(x[0].length);
      expect(matrix.rows).toBe(y.rows);
      expect(matrix.cols).toBe(y.cols);
      for (let i = 0; i < matrix.rows; i++) {
        for (let j = 0; j < matrix.cols; j++) {
          expect(matrix.get(i, j)).toBe(x[i][j]);
        }
      }
    });
  });

  describe('Transpose', () => {
    tester(VALID, (x: any, y: any) => {
      const matrix = new Matrix(x);
      const matrixT = matrix.transpose();
      expect(matrix.rows).toBe(matrixT.cols);
      expect(matrix.cols).toBe(matrixT.rows);
      for (let i = 0; i < matrix.rows; i++) {
        for (let j = 0; j < matrix.cols; j++) {
          expect(matrix.get(i, j)).toBe(matrixT.get(j, i));
        }
      }
    });
  });
});
