/*
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 *
 * An expiring LRU cache.
 *
 * Usage:
 *     var Cache = require('amon-common').Cache;
 *                                // size, expiry, log,  name
 *     this.accountCache = new Cache( 100,    300, log, 'account');
 *     this.accountCache.set('hamish', {...});
 *     ...
 *     this.accountCache.get('hamish')    // -> {...}
 */

import assert from 'assert'
import LRU from 'lru-cache'

interface CacheItem<T> {
  value: T
  ctime: number
}

/**
 * An LRU and expiring cache.
 */
export default class Cache {
  /**
   * Maximum number of entries to cache.
   */
  size: number
  /**
   * Number of milliseconds after which to expire entries.
   */
  expiry: number
  /**
   * Logger, if any, to use when logging events. All logging is done at the
   * trace level.
   */
  log: any
  /**
   * Name for the cache, used when logging.
   */
  name: string
  /**
   * The items contained in the cache.
   */
  items: LRU<string, CacheItem<any>>

  /**
   * Creates a new cache instance.
   * @param size Maximum number of entries to cache.
   * @param expiry Number of seconds after which to expire entries.
   * @param log Logger, if any, to use when logging events. All logging is done
   * at the trace level.
   * @param name Name for the cache, used when logging.
   */

  constructor(size: number, expiry: number, log: any, name: string) {
    assert.ok(size !== undefined)
    assert.ok(expiry !== undefined)

    this.size = size
    this.expiry = expiry * 1000
    this.log = log
    this.name = name ? name + ' ' : ''
    this.items = new LRU({ max: this.size })
  }

  #logTrace(formatString: string, ...args: unknown[]): void {
    if (this.log) {
      this.log.trace(formatString, ...args)
    }
  }

  /**
   * Clears the cache.
   */
  reset(): void {
    this.#logTrace('%scache reset', this.name)
    this.items.reset()
  }

  /**
   * Gets an object from the cache with the given key.
   * @param key The cache key.
   * @returns The cached value, or undefined if not found or expired.
   */
  get(key: string): any {
    assert.ok(key !== undefined)
    const cached = this.items.get(key)
    if (cached) {
      if (new Date().getTime() - cached.ctime <= this.expiry) {
        this.#logTrace('%scache hit: key="%s": %o', this.name, key, cached)
        return cached.value
      }
    }
    this.#logTrace('%scache miss: key="%s"', this.name, key)
  }

  /**
   * Sets a value in the cache for the given key.
   * @param key The cache key.
   * @param value The value to cache.
   * @returns The cached value and its expiry time.
   */
  set(key: string, value: unknown): CacheItem<any> {
    assert.ok(key !== undefined)
    const item = {
      value,
      ctime: new Date().getTime(),
    }
    this.#logTrace('%scache set: key="%s": %o', this.name, key, item)
    this.items.set(key, item)
    return Object.assign({}, item)
  }

  /**
   * Deletes a single entry with the given key from the cache.
   * @param key The cache key.
   */
  delete(key: string): void {
    this.#logTrace('%scache del: key="%s"', this.name, key)
    this.items.del(key)
  }
}
