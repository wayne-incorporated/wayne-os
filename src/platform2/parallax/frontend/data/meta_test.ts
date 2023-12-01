// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {MetaMap, MetaMapSet} from '@parallax/data/meta';

describe('MetaMap', () => {
  it('Valid filter', () => {
    const map =
        new MetaMap({'name': 'samples', 'test': '2', 'unfilterable': '3'});
    expect(map).toBeDefined();
  });
});
