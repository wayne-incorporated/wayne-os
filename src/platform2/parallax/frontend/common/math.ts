// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';

/**
 * Contains a matrix
 */
export class Matrix<T> {
  readonly numRows: number;
  readonly numCols: number;
  readonly array: T[][];

  /**
   * Creates new Matrix from an array of arrays.
   *
   * @param array Input matrix
   */
  constructor(array: ReadonlyArray<ReadonlyArray<T>>) {
    if (!Array.isArray(array)) {
      throw new ParallaxError('Input be a 2D-array', {'array': array});
    }
    this.numRows = array.length;
    this.numCols = array[0].length;
    for (const column of array) {
      if (!Array.isArray(column)) {
        throw new ParallaxError('Columns must be arrays', {'column': column});
      }
      if (column.length !== this.cols) {
        throw new ParallaxError(
            'Columns must be the same length',
            {'column.length': column.length, 'this.cols': this.cols});
      }
    }
    this.array = array;
  }

  /**
   * @return The number of rows
   */
  get rows() {
    return this.numRows;
  }

  /**
   * @return The number of columns
   */
  get cols() {
    return this.numCols;
  }

  /**
   * Creates a new Matrix as a transpose of the current matrix with the
   * rows and columns swapped.
   *
   * @return New Matrix with the same elements transposed.
   */
  transpose() {
    const array: T[][] = Array(this.cols);
    for (let i = 0; i < this.cols; i++) {
      array[i] = Array(this.rows);
      for (let j = 0; j < this.rows; j++) {
        array[i][j] = this.array[j][i];
      }
    }
    return new Matrix<T>(array);
  }

  /**
   * Get the value at a specific index.
   *
   * @param row Row number
   * @param col Column number
   * @return Value at the specific row and column number.
   */
  get(row: number, col: number) {
    return this.array[row][col];
  }

  /**
   * @return The raw array content.
   */
  asArray(): ReadonlyArray<ReadonlyArray<T>> {
    return this.array;
  }

  /**
   * @return The data in a JSON serializable format.
   */
  toJSON(): ReadonlyArray<ReadonlyArray<T>> {
    return this.array;
  }
}
