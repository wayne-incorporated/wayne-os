// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// eslint-disable-next-line
parallax.parseMessages([
  {
    'type': 'linechart',
    'meta': {'rowMeta': [{'chart': 'time'}, {'name': 'one'}, {'name': 'two'}]},
    'matrix': [
      [1, 2, 3, 4, 5],
      [10, 10, 20, 30, 40],
      [15, 5, 30, 20, 10],
    ],
  },
  {
    'type': 'linechart',
    'meta':
        {'rowMeta': [{'chart': 'time'}, {'name': 'three'}, {'name': 'four'}]},
    'matrix': [
      [3, 5, 7, 8, 9],
      [20, 20, 30, 40, 50],
      [25, 15, 40, 30, 20],
    ],
  },
  {
    'type': 'linechart',
    'meta': {'rowMeta': [{'chart': 'time'}, {'name': 'five'}, {'name': 'six'}]},
    'matrix': [
      [3, 5, 7, 8, 9],
      [20, 20, 30, 40, 50],
      [25, 15, 40, 30, 20],
    ],
  },
]);
