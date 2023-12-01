// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {TemplateName, cloneTemplate} from '@parallax/interface/doc';
import {tester} from '@parallax/common/test';

describe('cloneTemplate', () => {
  const ERROR = [
    {args: null},
    {args: undefined},
    {args: 'template-invalid'},
  ];

  describe('Invalid Test', () => {
    tester(ERROR, (x: any) => {
      expect(() => {
        cloneTemplate(x as TemplateName);
      }).toThrowError();
    });
  });


  describe('Valid Tests', () => {
    const names = Object.values(TemplateName).map((x) => {
      return {
        args: x,
      };
    });
    tester(names, (x: any) => {
      expect(() => {
        cloneTemplate(x as TemplateName);
      }).toBeDefined();
    });
  });
});
