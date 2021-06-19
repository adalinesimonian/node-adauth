/**
 * Copyright 2011 (c) Trent Mick.
 * Copyright 2015 (c) Adaline Valentina Simonian
 *
 * AD auth.
 *
 * Usage:
 *    var ADAuth = require('adauth');
 *    var auth = new ADAuth({url: 'ldaps://corp.example.com:636', ...});
 *    ...
 *    auth.authenticate(username, password, function (err, user) { ... });
 *    ...
 *    auth.close(function (err) { ... })
 */

import assert from 'assert'
import { EventEmitter } from 'events'
import fs from 'fs'
import { ConnectionOptions } from 'tls'
import fetch from 'make-fetch-happen'
import ldap from 'ldapjs'
import bcrypt from 'bcryptjs'
import validUrl from 'valid-url'
import Cache from './cache'
import {
  binarySIDToString,
  binaryGUIDToString,
  escapeADString,
} from './ad-utils'

/**
 * Gets a subset of the given object with the given keys.
 * @param obj Object to retrieve a subset of.
 * @param keys Keys to retrieve.
 * @returns A subset of the given object with the given keys.
 */
const getSubset = <T, K extends keyof T>(
  obj: T,
  ...keys: K[]
): { [key in keyof T]: T[key] } => {
  return keys.reduce((acc, key) => {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      acc[key] = obj[key]
    }
    return acc
  }, {} as { [key in keyof T]: T[key] })
}

namespace ADAuth {
  export type Scope = 'base' | 'one' | 'sub'

  export interface GroupSearchFilterFunction {
    /**
     * Construct a group search filter from user object
     *
     * @param user The user retrieved and authenticated from LDAP
     */
    (user: any): string
  }

  export interface Options extends ldap.ClientOptions {
    /**
     * The root DN of the AD domain, e.g. `dc=corp,dc=example,dc=com`.
     */
    domainDN: string
    /**
     * Not used in ADAuth.
     */
    bindDN?: undefined
    /**
     * Not used in ADAuth.
     */
    bindCredentials?: undefined
    /**
     * Optional, default is the domain DN. The base DN from which to search
     * for users by username.
     * E.g. ou=users,dc=example,dc=org
     */
    searchBase?: string
    /**
     * Optional, default `(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))`.
     * Search filter with which to find a user by FQDN.
     */
    searchFilterByDN?: string
    /**
     * Optional, default `(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))`.
     * Search filter with which to find a user by UPN. (user@domain.com)
     */
    searchFilterByUPN?: string
    /**
     * Optional, default `(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))`.
     * Search filter with which to find a user by their old-format Windows username.
     */
    searchFilterBySAN?: string
    /**
     * Scope of the search. Default: 'sub'
     */
    searchScope?: Scope
    /**
     * Array of attributes to fetch from LDAP server. Default: all
     */
    searchAttributes?: string[]

    /**
     * The base DN from which to search for groups. If defined,
     * also groupSearchFilter must be defined for the search to work.
     */
    groupSearchBase?: string
    /**
     * LDAP search filter for groups. Place literal {{dn}} in the filter
     * to have it replaced by the property defined with `groupDnProperty`
     * of the found user object. Optionally you can also assign a
     * function instead. The found user is passed to the function and it
     * should return a valid search filter for the group search.
     */
    groupSearchFilter?: string | GroupSearchFilterFunction
    /**
     * Scope of the search. Default: sub
     */
    groupSearchScope?: Scope
    /**
     * Array of attributes to fetch from LDAP server. Default: all
     */
    groupSearchAttributes?: string[]

    /**
     * Property of the LDAP user object to use when binding to verify
     * the password. E.g. name, email. Default: dn
     */
    bindProperty?: string
    /**
     * The property of user object to use in '{{dn}}' interpolation of
     * groupSearchFilter. Default: 'dn'
     */
    groupDNProperty?: string

    /**
     * Set to true to add property '_raw' containing the original buffers
     * to the returned user object. Useful when you need to handle binary
     * attributes
     */
    includeRaw?: boolean

    /**
     * If true, then up to 100 credentials at a time will be cached for
     * 5 minutes.
     */
    cache?: boolean

    /**
     * If true, then intialise TLS using the starttls mechanism.
     */
    starttls?: boolean
    /**
     * Provides the secure TLS options passed to tls.connect in ldapjs
     */
    tlsOptions?: ConnectionOptions
  }

  export interface SIDSearchOptions extends ldap.SearchOptions {
    /**
     * The base DN for the SID.
     */
    baseDN?: string
  }
}

// eslint-disable-next-line no-shadow
class ADAuth extends EventEmitter {
  readonly options: ADAuth.Options

  readonly clientOptions: ldap.ClientOptions

  #log: any

  #userCache?: Cache

  #salt: string
  #userClient: ldap.Client

  #getGroups: (user: any, options?: any) => Promise<any>

  #initialised = false

  /**
   * Instantiates a new ADAuth instance.
   * @param init ADAuth options.
   */
  constructor(init: ADAuth.Options) {
    super()

    assert.ok(init, 'Options not provided')
    assert.ok(
      init.url,
      'AD domain controller LDAP URL not defined (options.url)'
    )
    assert.ok(init.domainDN, 'Domain DN not defined (options.domainDN)')

    const options: ADAuth.Options = Object.assign(
      {
        searchBase: init.domainDN,
        groupSearchBase: init.domainDN,
        searchFilterByDN:
          '(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))',
        searchFilterByUPN:
          '(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))',
        searchFilterBySAN:
          '(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))',
        groupSearchFilter:
          '(&(objectCategory=group)(objectClass=group)(member={{dn}}))',
        searchScope: 'sub',
        bindProperty: 'dn',
        groupSearchScope: 'sub',
        groupDNProperty: 'dn',
      },
      init
    )
    this.options = options

    this.#log = options.log && options.log.child({ component: 'adauth' }, true)

    if (options.cache) {
      this.#userCache = new Cache(100, 300, this.#log, 'user')
    }

    this.clientOptions = getSubset(
      options,
      'url',
      'tlsOptions',
      'socketPath',
      'log',
      'timeout',
      'connectTimeout',
      'idleTimeout',
      'strictDN',
      'queueSize',
      'queueTimeout',
      'queueDisable'
    )

    if (options.groupSearchBase && options.groupSearchFilter) {
      if (typeof options.groupSearchFilter === 'string') {
        const { groupSearchFilter } = options
        options.groupSearchFilter = user =>
          groupSearchFilter
            .replace(/{{dn}}/g, user[options.groupDNProperty])
            .replace(/{{username}}/g, user.uid)
      }

      this.#getGroups = async (user, opts) => await this.#findGroups(user, opts)
    } else {
      this.#getGroups = async user => user
    }
  }

  /**
   * If a logger was provided, logs the given message at the trace level.
   * @param formatString Format string to pass to the logger.
   * @param args Arguments to pass to the logger.
   */
  #logTrace(formatString: string, ...args: any[]): void {
    if (this.#log) {
      this.#log.trace(formatString, ...args)
    }
  }

  /**
   * Logs and emits an error.
   * @param error The error to be logged and emitted.
   */
  #handleError(error: Error): void {
    this.#logTrace('LDAP-emitted error: %s', error)
    this.emit('error', error)
  }

  /**
   * Asserts that the instance is initialised.
   */
  #assertInitialised(): void {
    assert.ok(
      this.#initialised,
      'ADAuth instance is not initialised. Please call initialise() first.'
    )
  }

  /**
   * Conduct a search on the LDAP server.
   * Used for fetching both user and group information.
   *
   * @param searchBase LDAP search base
   * @param searchOptions LDAP search options
   */
  async #search(
    searchBase: string,
    searchOptions: ldap.SearchOptions = {}
  ): Promise<any[]> {
    this.#assertInitialised()
    const { includeRaw } = this.options

    return await new Promise((resolve, reject) => {
      this.#userClient.search(
        searchBase,
        searchOptions,
        (error, searchResult) => {
          if (error) {
            return reject(error)
          }

          const items = []
          searchResult.on('searchEntry', entry => {
            items.push({
              ...entry.object,
              objectSid: entry.raw.objectSid
                ? binarySIDToString(entry.raw.objectSid as Buffer)
                : undefined,
              objectGUID: entry.raw.objectGUID
                ? binaryGUIDToString(entry.raw.objectGUID as Buffer)
                : undefined,
              _raw: includeRaw ? entry.raw : undefined,
            })
          })

          searchResult.on('error', reject)

          searchResult.on('end', result => {
            if (result.status !== 0) {
              return reject(
                new Error(`Non-zero status from LDAP search: ${result.status}`)
              )
            }

            return resolve(items)
          })
        }
      )
    })
  }

  /**
   * Gets the user record for the given username.
   * @param username Username to search for
   * @param options LDAP search options
   * @returns User, if found, or undefined if not found.
   */
  async #findUser(
    username: string,
    options: ldap.SearchOptions = {}
  ): Promise<any> {
    this.#assertInitialised()
    if (!username) {
      throw new Error('empty username')
    }

    const {
      domainDN,
      searchBase,
      searchAttributes,
      searchFilterBySAN,
      searchFilterByUPN,
      searchScope,
    } = this.options

    let searchFilter

    if (username.includes('\\')) {
      const splitUsername = username.split('\\')
      const netBIOSDomainName = splitUsername[0]
      const samAccountName = splitUsername[1]

      const domains = await this.#search(domainDN, {
        filter: `(distinguishedName=${domainDN})`,
        attributes: ['msDS-PrincipalName'],
        scope: searchScope,
      })

      let inName = netBIOSDomainName.toUpperCase()
      if (inName.charAt(inName.length - 1) === '\\') {
        inName = inName.substring(0, inName.length - 1)
      }
      let fdName = domains[0]['msDS-PrincipalName'].toUpperCase()
      if (fdName.charAt(fdName.length - 1) === '\\') {
        fdName = fdName.substring(0, fdName.length - 1)
      }
      if (inName === fdName) {
        searchFilter = searchFilterBySAN.replace(
          /{{username}}/g,
          escapeADString(samAccountName)
        )
      } else {
        const errorMsg = `cannot find known domain with netBIOS domain name ${netBIOSDomainName}`

        this.#logTrace(errorMsg)
        throw new Error(errorMsg)
      }
    } else if (username.includes('@')) {
      searchFilter = searchFilterByUPN.replace(
        /{{upn}}/g,
        escapeADString(username)
      )
    } else {
      searchFilter = searchFilterBySAN.replace(
        /{{username}}/g,
        escapeADString(username)
      )
    }

    let result: any[]
    try {
      result = await this.#search(searchBase, {
        ...options,
        filter: searchFilter,
        scope: searchScope,
        attributes: searchAttributes || undefined,
      })
    } catch (error) {
      this.#logTrace(
        'AD authenticate: user search error: %s %s %s',
        error.code,
        error.name,
        error.message
      )
      throw error
    }

    switch (result.length) {
      case 0:
        return
      case 1:
        return result[0]
      default:
        throw new Error(
          `Unexpected number of matches (${result.length}) for username "${username}"`
        )
    }
  }

  /**
   * Gets the object with the given SID.
   * @param sid The SID of the object to find.
   * @param options LDAP search options
   * @returns The object with the given SID, or undefined if no matching
   * object is found.
   */
  async #findObjectBySID(
    sid: string | number[],
    options: ADAuth.SIDSearchOptions = {}
  ): Promise<any> {
    this.#assertInitialised()
    const sidString =
      typeof sid !== 'string' && Array.isArray(sid)
        ? binarySIDToString(sid)
        : sid

    const baseDN = options.baseDN || this.options.domainDN
    const { groupSearchScope } = this.options

    try {
      const result = await this.#search(baseDN, {
        ...options,
        filter: `(objectSid=${sidString})`,
        scope: groupSearchScope,
      })
      return result && result[0]
    } catch (error) {
      this.#logTrace(
        'Find object by SID: search error: %s %s %s',
        error.code,
        error.name,
        error.message
      )
    }
  }

  /**
   * Gets groups for the given user.
   * @param user The LDAP user object
   * @param options LDAP search options
   * @returns The user object with groups attached.
   */
  async #findGroups(
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    user: any,
    options: ldap.SearchOptions = {}
  ): Promise<any[]> {
    this.#assertInitialised()
    if (!user) {
      throw new Error('No user')
    }

    const objGroups = []
    const resolved = new Set()

    const {
      groupSearchFilter,
      groupSearchScope,
      groupDNProperty,
      groupSearchBase,
      groupSearchAttributes,
    } = this.options

    // Recursively fetch effective group membership because AD's recursive
    // group membership filter is incredibly slow (running 20 separate
    // queries through this method is 5-10x faster than a single query using
    // the filter).
    const resolveGroups = async obj => {
      if (!obj) {
        throw new Error(
          'AD authenticate: Cannot find groups for undefined object'
        )
      }

      const searchFilter =
        typeof groupSearchFilter === 'string'
          ? groupSearchFilter.replace(/{{dn}}/g, obj[groupDNProperty])
          : groupSearchFilter(obj)

      const searchOptions = {
        ...options,
        filter: searchFilter,
        scope: groupSearchScope,
        attributes: groupSearchAttributes,
      }

      let groups: any[]
      try {
        groups = await this.#search(groupSearchBase, searchOptions)
      } catch (error) {
        this.#logTrace(
          'AD authenticate: group search error: %s %s %s',
          error.code,
          error.name,
          error.message
        )
        throw error
      }

      // Primary group is not returned by group membership query. Instead, the
      // SID for the group must be determined based on objectSID and the
      // primaryGroupID, and then queried against the directory.
      if (obj.primaryGroupID) {
        const primaryGroupSID =
          obj.objectSid.substring(0, obj.objectSid.lastIndexOf('-') + 1) +
          obj.primaryGroupID

        let primaryGroup
        try {
          primaryGroup = await this.#findObjectBySID(
            primaryGroupSID,
            searchOptions
          )
        } catch (error) {
          this.#logTrace(
            'Find primary group by SID: search error: %s %s %s',
            error.code,
            error.name,
            error.message
          )
          throw error
        }

        if (primaryGroup) {
          groups.unshift(primaryGroup)
          if (Array.isArray(obj.memberOf)) {
            obj.memberOf.unshift(primaryGroup.dn)
          } else if (obj.memberOf) {
            obj.memberOf = [primaryGroup.dn, obj.memberOf]
          }
        }
      }

      const needResolution = []

      for (const group of groups) {
        if (!resolved.has(group.objectSid)) {
          resolved.add(group.objectSid)
          needResolution.push(group)
          objGroups.push(group)
        }
      }

      await Promise.all(
        needResolution.map(group => async () => {
          try {
            await resolveGroups(group)
          } catch (error) {
            this.#handleError(error)
            throw error
          }
        })
      )
    }

    try {
      await resolveGroups(user)
    } catch (error) {
      this.#logTrace(
        'AD authenticate: group search error: %s %s %s',
        error.code,
        error.name,
        error.message
      )
      throw error
    }

    return objGroups
  }

  /**
   * Initialises the ADAuth instance.
   */
  async initialise(): Promise<void> {
    if (this.#userCache) {
      this.#salt = await bcrypt.genSalt()
    }

    const { tlsOptions, starttls } = this.options

    if (typeof tlsOptions?.ca === 'string') {
      const { ca } = tlsOptions
      try {
        if (validUrl.isWebUri(ca)) {
          const response = await fetch(ca, { method: 'GET' })
          if (!response.ok) {
            throw new Error(
              `Failure getting CA certificate: received response code ${response.status}`
            )
          }
          tlsOptions.ca = await response.buffer()
        } else {
          tlsOptions.ca = fs.readFileSync(ca)
        }
      } catch (error) {
        this.#handleError(error)
      }
    }

    this.#userClient = ldap.createClient(this.clientOptions)

    this.#userClient.on('error', error => this.#handleError(error))

    if (starttls) {
      this.#userClient.starttls(
        tlsOptions,
        undefined,
        error => error && this.#handleError(error)
      )
    }

    this.#userClient.on('connectTimeout', error => this.#handleError(error))

    this.#initialised = true
  }

  /**
   * Instantiates a new, initialised ADAuth instance.
   * @param init ADAuth options.
   * @returns The new, initialised ADAuth instance.
   */
  static async create(init: ADAuth.Options): Promise<ADAuth> {
    const auth = new ADAuth(init)
    await auth.initialise()
    return auth
  }

  /**
   * Authenticates given credentials against an AD server.
   *
   * @param username The username to authenticate
   * @param password The password to verify
   * @returns The user object with the groups the user belongs to.
   */
  async authenticate(username: string, password: string): Promise<any> {
    this.#assertInitialised()
    if (!password) {
      throw new Error('No password provided')
    }

    if (this.#userCache) {
      // Check cache. cached is `{password: <hashed-password>, user: <user>}`.
      const cached = this.#userCache.get(username)
      if (cached && (await bcrypt.compare(password, cached.password))) {
        return cached.user
      }
    }

    // 1. Attempt to bind with the give credentials to validate them
    //
    // We are authenticating first so that AD can log failed signin attempts,
    // apply necessary user lockout policies, and so that it is harder to run
    // a list of usernames against the AD domain controller to see which ones
    // exist based on response time (binding causes an unavoidable delay).
    try {
      await new Promise<void>((resolve, reject) => {
        this.#userClient.bind(username, password, error => {
          if (error) {
            return reject(error)
          }

          resolve()
        })
      })
    } catch (error) {
      this.#logTrace('AD authenticate: bind error: %s', error)
      throw error
    }

    // 2. Find the user DN in question.
    const user = await this.#findUser(username)

    if (!user) {
      throw new Error(`No such user: "${username}"`)
    }

    // 3. Fetch user groups
    let groups
    try {
      groups = await this.#getGroups(user)
    } catch (error) {
      this.#logTrace('AD authenticate: group search error: %s', error)
      throw error
    }

    const userWithGroups = Object.assign({}, user, { groups })

    // 4. Cache result if using cache
    if (this.#userCache) {
      try {
        const hash = await bcrypt.hash(password, this.#salt)

        this.#userCache.set(username, {
          password: hash,
          user: userWithGroups,
        })
      } catch (error) {
        this.#logTrace('AD authenticate: bcrypt error, not caching %s', error)
      }
    }

    return userWithGroups
  }

  /**
   * Unbinds connections.
   */
  async close(): Promise<void> {
    this.#assertInitialised()
    await new Promise<void>(resolve => {
      this.#userClient.unbind(() => resolve())
    })
  }

  /**
   * Disposes client and prevents reconnection.
   */
  async dispose(): Promise<void> {
    if (this.#initialised) {
      await this.close()
      this.#initialised = false
      this.#userClient.destroy()
      this.#userClient = undefined
    }
  }
}

export default ADAuth
