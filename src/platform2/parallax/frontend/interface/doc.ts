// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';

export enum TemplateName {
  TEMPLATE_PLOT_ROW = 'template-plot-row',
  TEMPLATE_SELECTOR_COLUMN = 'template-selector-column',
  TEMPLATE_SELECTOR_ENTRY = 'template-selector-entry',
}

export enum ClassName {
  PLOT_LIST = 'plot-list',
  RESULT_LIST = 'results-list',
  PLOT_AREA = 'plot-area',
}

/**
 * Clones a specific template.
 *
 * @param templateName Template name we wish to clone.
 * @return A copy of the HTMLElement within the template.
 */
export function cloneTemplate(templateName: TemplateName) {
  const template = document.getElementById(templateName) as HTMLTemplateElement;
  if (!template) {
    throw new ParallaxError(
        'Template not found', {'templateName': templateName});
  }
  const element = template?.content?.firstElementChild as HTMLElement;
  if (!element) {
    throw new ParallaxError(
        'Element not found', {'templateName': templateName});
  }
  const clone = element.cloneNode(true) as HTMLElement;
  return clone;
}

/**
 * Find the requested class within the container.
 *
 * @param root      Base container which can be the Document or a HTMLElement
 * @param className Class we want to find.
 * @return A collection of all matched HTMLElement from the container.
 */
export function findElementsByClass(
    root: Document|HTMLElement, className: ClassName) {
  let elements: HTMLElement[] = [];
  for (let elem of root.getElementsByClassName(className)) {
    if (elem instanceof HTMLElement) {
      elements.push(elem);
    } else {
      console.warn('Invalid type found', elem);
    }
  }
  return elements;
}
