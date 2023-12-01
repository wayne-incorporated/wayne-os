// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

const fs = require('fs');
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin');

const SRC_DIR = 'frontend';
const DST_DIR = path.resolve(__dirname, 'dist');

// We need to erase the destination directory. The output.clean option
// does not work well with multiple entries sharing the same directory.
fs.rmdirSync(DST_DIR, {recursive: true});

function generate(name, flags = []) {
  const validFlags = ['test', 'embedded', 'minify', 'debug', 'map'];
  let invalidFlags = flags.filter(x => !validFlags.includes(x));
  if (invalidFlags.length) {
    console.error('Error: Unknown Flags:', invalidFlags);
  }
  let entry = flags.includes('test') ? 'test' : 'report';
  let mode = flags.includes('debug') ? 'development' : 'production';
  let minify = flags.includes('minify') ? true : false;
  let devtool = flags.includes('map') ? 'inline-source-map' : undefined;
  let config = {
    name: name,
    mode: mode,
    entry: path.resolve(SRC_DIR, entry + '.ts'),
    devtool: devtool,
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
      ],
    },
    plugins: [
      new HtmlWebpackPlugin({
        filename: name + '.html',
        template: path.resolve(SRC_DIR, 'template.ejs'),
        templateParameters: flags,
        minify: minify,
        inject: false,
      }),
    ],
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
      alias: {
        '@parallax': path.resolve(__dirname, SRC_DIR),
      },
    },
    optimization: {
      minimize: minify,
    },
    output: {
      clean: false,
      path: DST_DIR,
      library: 'parallax',
    },
  };

  return config;
}



module.exports = [
  generate('release', ['minify']),
  generate('report', ['embedded', 'map']),
  generate('report_debug', ['embedded', 'debug']),
  generate('test', ['test', 'map']),
  generate('test_debug', ['test', 'debug']),
]
