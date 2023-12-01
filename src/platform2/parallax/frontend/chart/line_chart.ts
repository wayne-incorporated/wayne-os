// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {addChart, updateChart} from '@parallax/data/manager';
import {Chart} from '@parallax/chart/chart';
import {Matrix} from '@parallax/common/math';
import {ParallaxError} from '@parallax/common/error';
import {registerParser} from '@parallax/data/parse';
import {PlotRow} from '@parallax/interface/plot_row';

/**
 * Contains a LineChart featuring a set of meta data and 2D-arrays of samples.
 *
 * Meta data access:
 *     meta = data['meta']
 *     type = meta['type']
 *
 * Measurements are stored in a matrix where a row will typically represent
 * an individual sensor or timestamp. Columns represent samples measured
 * at the same time.
 *
 *    Row meta data access:
 *        rolMeta = data['rowMeta']
 *        rolName = rolMeta[rowNum]['name']
 *        rolCount = len(data['rowMeta'])
 *    Shape access:
 *        matrix = data['matrix']
 *        colCount = len(matrix)
 *        rowCount = len(matrix[0])
 *    Data access:
 *        cellValue = matrix[rowNum][colNum]
 *        colValues = matrix[rowNum]
 *        rowValues = [matrix[x][colNum] for x in range(colCount)]
 */
export class LineChart extends Chart {
  private meta: any;
  private matrix: Matrix<any>;
  private dataTable: google.visualization.DataTable|undefined;
  private dataView: google.visualization.DataView|undefined;

  /**
   * Creates a new LineChart.
   *
   * @param meta   Chart meta data.
   * @param matrix Chart sample data as a 2D-array.
   */
  constructor(meta: any, matrix: any) {
    super(meta?.rowMeta);
    this.matrix = new Matrix<any>(matrix);
    this.meta = meta;

    if (this.matrix.rows === 0 || this.matrix.rows !== this.axisMeta.length) {
      throw new Error('Invalid number of columns');
    }
  }

  /**
   * Renders the plot.
   * TODO (bnemec): Replace mock.
   *
   * @param plotRow PlotRow we are rending inside.
   */
  draw(plotRow: PlotRow) {
    console.log('LineChart.draw()');
    let dataView = this.configureView();
    let options = {
      fontSize: 14,
      interpolateNulls: false,
      legend: {
        maxLines: 3,
      },
      chartArea: {
        left: 50,
        width: plotRow.plotArea.clientWidth - 100,
        top: 100,
        height: plotRow.plotArea.clientHeight - 200,
      },
      explorer: {
        maxZoomIn: 0,
        keepInBounds: true,
        actions: ['dragToZoom', 'rightClickToReset'],
      },
      hAxis: {
        format: 'hh:mm:ss a',
      },
    };
    // @ts-ignore: The ChartLegendPosition guard is rejecting all values.
    options.legend.position = 'top';

    let chart = new google.visualization.LineChart(plotRow.plotArea);

    // Define the columns as assign names
    let columns = [];
    for (const [index, axis] of this.axisMeta.entries()) {
      let name = axis.getMeta().get('name');
      if (typeof name !== 'string') {
        name = index.toString();
      }

      let value: any = {
        label: name,
        sourceColumn: index,
      };

      // The value in index 0 is the unix time, we transform
      // the unix time format to user readable time format
      if (index === 0) {
        value['type'] = 'datetime';
        // The calculate function could transform the time format
        value['calc'] =
            ((dataTable: google.visualization.DataTable, row: number) => {
              let unixtime = dataTable.getValue(row, index) as number;
              // Get the data in millisecond
              let time = new Date(unixtime * 1000);
              return time;
            });
      }
      columns.push(value);
    }

    dataView.setColumns(columns);
    chart.draw(dataView, options);
  }

  /**
   * Configures the DataView.
   * TODO (bnemec): Replace mock.
   *
   * @return A configured DataView
   */
  protected configureView() {
    const transposed = this.matrix.transpose();
    if (this.dataView === undefined) {
      this.dataTable = google.visualization.arrayToDataTable(
          transposed.asArray() as any[], true);
      this.dataView = new google.visualization.DataView(this.dataTable);
    }
    return this.dataView;
  }

  /**
   * @returns The JSON serializable representation.
   */
  toJSON() {
    return {
      'type': 'linechart',
      'meta': this.meta,
      'matrix': this.matrix,
    };
  }
}

registerParser((data: any) => {
  if (data.type === 'linechart') {
    const chart = new LineChart(data.meta, data.matrix);
    addChart(chart);
  }
});

registerParser((data: any) => {
  if (data.type === 'streaming_chart') {
    const chart = new LineChart(data.meta, data.matrix);
    updateChart(chart);
    const stream = new CustomEvent('stream', {'detail': {'chart': chart}});
    document.dispatchEvent(stream);
  }
});
