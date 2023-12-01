// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';
import {cloneTemplate, findElementsByClass, TemplateName, ClassName} from '@parallax/interface/doc';
import {getChart} from '@parallax/data/manager';

let plots: PlotRow[] = [];

/**
 *
 */
export class PlotRow {
  readonly dom: HTMLElement;
  readonly plotArea: HTMLElement;
  readonly resizerObs: ResizeObserver;

  /**
   * [constructor description]
   */
  constructor() {
    this.dom = cloneTemplate(TemplateName.TEMPLATE_PLOT_ROW);
    let container = findElementsByClass(document, ClassName.PLOT_LIST)[0];
    this.plotArea = findElementsByClass(this.dom, ClassName.PLOT_AREA)[0];
    this.resizerObs = new ResizeObserver(() => {
      this.draw();
    });
    this.resizerObs.observe(this.plotArea);
    container.appendChild(this.dom);
    // TODO bnemec Cleanup so the redraws only happen when we get new data
    // for streaming charts and ignores others.
    document.addEventListener('stream', this.draw.bind(this));
  }

  /**
   * Draw the chart.
   */
  draw() {
    console.log('PlotRow.draw()');
    let chart = getChart();
    chart.draw(this);
  }
}

/**
 * [newPlot description]
 */
export function newPlot() {
  let plot = new PlotRow();
  plots.push(plot);
}
