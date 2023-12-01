// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {iterableMap, isArrayLike} from '@parallax/common/helpers';

const FILTER_FIELDS =
    ['test', 'subtest', 'loop', 'phase', 'webpage', 'file', 'name'];

export const UNDEFINED_FILTER = 'Undefined';

/**
 * Represents the meta and filter fields for section of data. This allows us
 * track additional properties used to help select data or render.
 */
export class MetaMap {
  protected meta: Map<string, any>;

  /**
   * Creates a new MetaMap
   *
   * @param meta A map like object we will parse.
   */
  constructor(meta: any) {
    this.meta = new Map(iterableMap(meta));
  }

  /**
   * Checks the MetaMap's filter fields against the FilterMap.
   *
   * @param {MetaMapSet} filter [description]
   * @return True if all fields within the FilterMap
   */
  checkMatch(filter: MetaMapSet) {
    for (const [field, valid] of filter.getMap()) {
      const ourEntry = this.meta.get(field);
      if (ourEntry === undefined || !valid.has(ourEntry)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns all of the meta data
   *
   * @returns ReadOnly Map
   */
  getMeta() {
    return this.meta as ReadonlyMap<string, any>;
  }

  /**
   * @returns The JSON serializable representation.
   */
  toJSON() {
    return Object.fromEntries(this.meta);
  }
}

/**
 * MetaMapSets represent a union of multiple MetaMap key:value attributes.
 */
export class MetaMapSet {
  protected map = new Map<string, Set<string>>();

  /**
   * Joins the fields from several MetaMaps or FilterMaps together
   * to produce a union of the dictionaries.
   *
   * @param {ReadonlyArray<MetaMap>} metas [description]
   */
  constructor(metas?: any) {
    if (metas) {
      this.addMeta(metas);
    }
  }

  /**
   * [addMeta description]
   * @param {Map<string, string|Set<string>>} meta [description]
   */
  addMeta(meta: Map<string, string|Set<string>>) {
    for (const [field, values] of iterableMap(meta)) {
      let fieldSet = this.map.get(field);
      if (fieldSet === undefined) {
        fieldSet = new Set<string>();
        this.map.set(field, fieldSet);
      }
      if (isArrayLike(values)) {
        for (const value of values) {
          fieldSet.add(value);
        }
      } else {
        fieldSet.add(values);
      }
    }
  }

  /**
   * @returns The JSON serializable representation.
   */
  toJSON() {
    return Object.fromEntries(this.map);
  }

  /**
   * @returns A Map representation of the object.
   */
  getMap() {
    return this.map as ReadonlyMap<string, Set<string>>;
  }
}
