// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {getCleanHtml, injectIntoHtml} from '@parallax/data/save_html';

describe('Save HTML', () => {
  const cleanHTML = getCleanHtml();
  const injectionText = '\nconst DATA = "[]"\n';

  it('Verify tags', () => {
    const start = injectIntoHtml(cleanHTML, injectionText);
    expect(start).toBeDefined();
  });
  it('Verify injection', () => {
    const start = injectIntoHtml(cleanHTML, injectionText);
    const test = injectIntoHtml(start, injectionText + ';');
    expect(start).not.toEqual(test);
  });
  it('Verify repeatability', () => {
    const start = injectIntoHtml(cleanHTML, injectionText);
    const test = injectIntoHtml(start, injectionText);
    expect(start).toEqual(test);
  });
});
