// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {MetaMapSet, MetaMap} from '@parallax/data/meta';
import {ParallaxError} from '@parallax/common/error';
import {PlotRow} from '@parallax/interface/plot_row';

/**
 * Generic abstract class to handle any drawable chart.
 */
export abstract class Chart {
  protected axisMeta: MetaMap[] = [];

  /**
   * Assigns metadata fields to the chart for lookup.
   *
   * @param metas Metadata associated with the chart.
   */
  constructor(metas: any) {
    if (!Array.isArray(metas)) {
      throw new ParallaxError('Meta data must be an array', metas);
    }
    for (const meta of metas) {
      this.axisMeta.push(new MetaMap(meta));
    }
  }

  /**
   * Draws the plot
   * @param plot PlotRow
   */
  abstract draw(plotRow: PlotRow): void;
}
