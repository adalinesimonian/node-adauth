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

var assert = require('assert')
var Long = require('long')
var ldap = require('ldapjs')
var format = require('util').format
var bcrypt = require('bcryptjs')
var inherits = require('util').inherits
var EventEmitter = require('events').EventEmitter
var validUrl = require('valid-url')
var syncRequest = require('sync-request')
var fs = require('fs')

/**
 * Void callback
 *
 * @callback voidCallback
 * @param {(Error|undefined)} err - Possible error
 */
/**
 * Result callback
 *
 * @callback resultCallback
 * @param {(Error|undefined)} err - Possible error
 * @param {(Object|undefined)} res - Result
 */

/**
 * Get option that may be defined under different names, but accept
 * the first one that is actually defined in the given object
 *
 * @private
 * @param {object} obj - Config options
 * @param {string[]} keys - List of keys to look for
 * @return {*} The value of the first matching key
 */
var getOption = function (obj, keys) {
  for (var i = 0; i < keys.length; i++) {
    if (keys[i] in obj) {
      return obj[keys[i]]
    }
  }
  return undefined
}

/**
 * Create an AD auth class. Primary usage is the `.authenticate` method.
 *
 * @param {Object} opts - Config options
 * @constructor
 */
function ADAuth(opts) {
  this.opts = opts
  assert.ok(opts.url, 'AD domain controller LDAP URL not defined (opts.url)')
  opts.domainDN = getOption(opts, ['domainDn', 'domainDN'])
  assert.ok(opts.domainDN, 'Domain DN not defined (opts.domainDN)')
  opts.searchBase = opts.searchBase || opts.domainDN
  opts.groupSearchBase = opts.groupSearchBase || opts.domainDN
  opts.searchFilterByDN =
    opts.searchFilterByDN ||
    '(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))'
  opts.searchFilterByUPN =
    opts.searchFilterByUPN ||
    '(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))'
  opts.searchFilterBySAN =
    opts.searchFilterBySAN ||
    '(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))'
  opts.groupSearchFilter =
    opts.groupSearchFilter ||
    '(&(objectCategory=group)(objectClass=group)(member={{dn}}))'

  this.log = opts.log && opts.log.child({ component: 'adauth' }, true)

  this.opts.searchScope || (this.opts.searchScope = 'sub')
  this.opts.bindProperty || (this.opts.bindProperty = 'dn')
  this.opts.groupSearchScope || (this.opts.groupSearchScope = 'sub')
  this.opts.groupDnProperty || (this.opts.groupDnProperty = 'dn')

  EventEmitter.call(this)

  if (opts.cache) {
    // eslint-disable-next-line global-require
    var Cache = require('./cache')
    this.userCache = new Cache(100, 300, this.log, 'user')
    this._salt = bcrypt.genSaltSync()
  }

  if (
    opts.tlsOptions &&
    opts.tlsOptions.ca &&
    typeof opts.tlsOptions.ca === 'string'
  ) {
    if (validUrl.isWebUri(opts.tlsOptions.ca)) {
      var cert = syncRequest('GET', opts.tlsOptions.ca)
      opts.tlsOptions.ca = cert.getBody()
    } else {
      try {
        opts.tlsOptions.ca = fs.readFileSync(opts.tlsOptions.ca)
      } catch (err) {
        this._handleError(err)
      }
    }
  }

  this.clientOpts = {
    url: opts.url,
    tlsOptions: opts.tlsOptions,
    socketPath: opts.socketPath,
    log: opts.log,
    timeout: opts.timeout,
    connectTimeout: opts.connectTimeout,
    idleTimeout: opts.idleTimeout,
    reconnect: opts.reconnect,
    strictDN: opts.strictDN,
    queueSize: opts.queueSize,
    queueTimeout: opts.queueTimeout,
    queueDisable: opts.queueDisable,
    maxConnections: opts.maxConnections,
    checkInterval: opts.checkInterval,
    maxIdleTime: opts.maxIdleTime,
  }

  // Not passed to ldapjs, don't want to autobind
  // https://github.com/mcavage/node-ldapjs/blob/v1.0.1/lib/client/client.js#L343-L356
  this.bindDN = getOption(opts, ['bindDn', 'bindDN', 'adminDn'])
  this.bindCredentials = getOption(opts, [
    'bindCredentials',
    'Credentials',
    'adminPassword',
  ])

  this._adminClient = ldap.createClient(this.clientOpts)
  this._adminBound = false
  this._userClient = ldap.createClient(this.clientOpts)

  this._adminClient.on('error', this._handleError.bind(this))
  this._userClient.on('error', this._handleError.bind(this))

  var self = this
  if (this.opts.starttls) {
    // When starttls is enabled, this callback supplants the 'connect' callback
    this._adminClient.starttls(
      this.opts.tlsOptions,
      this._adminClient.controls,
      function (err) {
        if (err) {
          self._handleError(err)
        } else {
          self._onConnectAdmin()
        }
      }
    )
    this._userClient.starttls(
      this.opts.tlsOptions,
      this._userClient.controls,
      function (err) {
        if (err) {
          self._handleError(err)
        }
      }
    )
  } else if (opts.reconnect) {
    this.once('_installReconnectListener', function () {
      self.log && self.log.trace('install reconnect listener')
      self._adminClient.on('connect', function () {
        self._onConnectAdmin()
      })
    })
  }

  this._adminClient.on('connectTimeout', this._handleError.bind(this))
  this._userClient.on('connectTimeout', this._handleError.bind(this))

  if (opts.groupSearchBase && opts.groupSearchFilter) {
    if (typeof opts.groupSearchFilter === 'string') {
      var groupSearchFilter = opts.groupSearchFilter
      opts.groupSearchFilter = function (user) {
        return groupSearchFilter
          .replace(/{{dn}}/g, user[opts.groupDnProperty])
          .replace(/{{username}}/g, user.uid)
      }
    }

    this._getGroups = this._findGroups
  } else {
    // Assign an async identity function so there is no need to branch
    // the authenticate function to have cache set up.
    this._getGroups = function (user, callback) {
      return callback(null, user)
    }
  }
}

inherits(ADAuth, EventEmitter)

/**
 * Unbind connections
 *
 * @param {voidCallback} callback - Callback
 * @returns {undefined}
 */
ADAuth.prototype.close = function (callback) {
  var self = this
  // It seems to be OK just to call unbind regardless of if the
  // client has been bound (e.g. how ldapjs pool destroy does)
  self._adminClient.unbind(function () {
    self._userClient.unbind(callback)
  })
}

/**
 * Mark admin client unbound so reconnect works as expected and re-emit the error
 *
 * @private
 * @param {Error} err - The error to be logged and emitted
 * @returns {undefined}
 */
ADAuth.prototype._handleError = function (err) {
  this.log && this.log.trace('ldap emitted error: %s', err)
  this._adminBound = false
  this.emit('error', err)
}

/**
 * Bind adminClient to the admin user on connect
 *
 * @private
 * @param {voidCallback} callback - Callback that checks possible error, optional
 * @returns {undefined}
 */
ADAuth.prototype._onConnectAdmin = function (callback) {
  var self = this

  // Anonymous binding
  if (typeof self.bindDN === 'undefined' || self.bindDN === null) {
    self._adminBound = true
    return callback ? callback() : null
  }

  self.log && self.log.trace('AD authenticate: bind: %s', self.bindDN)
  self._adminClient.bind(self.bindDN, self.bindCredentials, function (err) {
    if (err) {
      self.log && self.log.trace('AD authenticate: bind error: %s', err)
      self._adminBound = false
      return callback ? callback(err) : null
    }

    self.log && self.log.trace('AD authenticate: bind ok')
    self._adminBound = true
    if (self.opts.reconnect) {
      self.emit('_installReconnectListener')
    }
    return callback ? callback() : null
  })
}

/**
 * Ensure that `this._adminClient` is bound.
 *
 * @private
 * @param {voidCallback} callback - Callback that checks possible error
 * @returns {undefined}
 */
ADAuth.prototype._adminBind = function (callback) {
  if (this._adminBound) {
    return callback()
  }

  // Call the connect handler with a callback
  return this._onConnectAdmin(callback)
}

/**
 * Conduct a search using either the user or admin client (admin by default).
 * Used for fetching both user and group information.
 *
 * @private
 * @param {string} searchBase - LDAP search base
 * @param {Object} options - LDAP search options
 * @param {boolean} options.userClient - If true, the user client is used
 * instead of the admin client.
 * @param {string} options.filter - LDAP search filter
 * @param {string} options.scope - LDAP search scope
 * @param {(string[]|undefined)} options.attributes - Attributes to fetch
 * @param {resultCallback} callback - The result handler callback
 * @returns {undefined}
 */
ADAuth.prototype._search = function (searchBase, options, callback) {
  var self = this

  var bindFunc = options.userClient
    ? function (cb) {
        cb()
      }
    : self._adminBind

  var ldapClient = options.userClient ? options.userClient : self._adminClient

  bindFunc(function (bindErr) {
    if (bindErr) {
      return callback(bindErr)
    }

    ldapClient.search(searchBase, options, function (searchErr, searchResult) {
      if (searchErr) {
        return callback(searchErr)
      }

      var items = []
      searchResult.on('searchEntry', function (entry) {
        var obj = entry.object
        obj.objectSid = entry.raw.objectSid
          ? self._binarySIDToString(entry.raw.objectSid)
          : undefined
        obj.objectGUID = entry.raw.objectGUID
          ? self._binaryGUIDToString(entry.raw.objectGUID)
          : undefined
        if (self.opts.includeRaw === true) {
          obj._raw = entry.raw
        }
        items.push(obj)
      })

      searchResult.on('error', callback)

      searchResult.on('end', function (result) {
        if (result.status !== 0) {
          var err = 'non-zero status from LDAP search: ' + result.status
          return callback(err)
        }
        return callback(null, items)
      })
    })
  })
}

/**
 * Find the user record for the given username.
 *
 * @param {string} username - Username to search for
 * @param {Object} options LDAP search options
 * @param {string} options.filter - LDAP search filter
 * @param {string} options.scope - LDAP search scope
 * @param {(string[]|undefined)} options.attributes - Attributes to fetch
 * @param {resultCallback} callback Result handling callback. If user is
 * not found but no error happened, result is undefined.
 * @returns {undefined}
 */
ADAuth.prototype._findUser = function (username, options, callback) {
  var self = this
  var opts = options || {}
  if (!username) {
    return callback(new Error('empty username'))
  }

  var searchFilter
  var validateQuery = function (cb) {
    cb()
  }

  if (username.indexOf('\\') !== -1) {
    // If using Domain\username form, ensure that Domain is the domain's actual
    // NetBIOS name and not just any arbitrary text
    var splitUsername = username.split('\\')
    var netBIOSDomainName = splitUsername[0]
    var sAMAccountName = splitUsername[1]

    validateQuery = function (cb) {
      var vopts = {
        filter: format('(distinguishedName=%s)', self.opts.domainDn),
        attributes: ['msDS-PrincipalName'],
        scope: self.opts.searchScope,
        userClient: opts.userClient,
      }

      self._search(self.opts.domainDn, vopts, function (err, domains) {
        if (err) {
          self._handleError(err)
          return
        }

        var inName = netBIOSDomainName.toUpperCase()
        if (inName.charAt(inName.length - 1) === '\\') {
          inName = inName.substring(0, inName.length - 1)
        }
        var fdName = domains[0]['msDS-PrincipalName'].toUpperCase()
        if (fdName.charAt(fdName.length - 1) === '\\') {
          fdName = fdName.substring(0, fdName.length - 1)
        }
        if (inName === fdName) {
          searchFilter = self.opts.searchFilterBySAN.replace(
            /{{username}}/g,
            self._escapeADString(sAMAccountName)
          )
          return cb()
        } else {
          var errMsg = format(
            'cannot find known domain with netBIOS domain name %s',
            netBIOSDomainName
          )
          self.log && self.log.trace(errMsg)
          return cb(new Error(errMsg))
        }
      })
    }
  } else if (username.indexOf('@') !== -1) {
    searchFilter = self.opts.searchFilterByUPN.replace(
      /{{upn}}/g,
      self._escapeADString(username)
    )
  } else {
    searchFilter = self.opts.searchFilterBySAN.replace(
      /{{username}}/g,
      self._escapeADString(username)
    )
  }

  validateQuery(function (err) {
    if (err) {
      return callback(err)
    }

    var validateOpts = {
      filter: searchFilter,
      scope: self.opts.searchScope,
      userClient: opts.userClient,
    }

    if (self.opts.searchAttributes) {
      validateOpts.attributes = self.opts.searchAttributes
    }

    self._search(
      self.opts.searchBase,
      validateOpts,
      function (searchErr, result) {
        if (searchErr) {
          self.log &&
            self.log.trace(
              'AD authenticate: user search error: %s %s %s',
              searchErr.code,
              searchErr.name,
              searchErr.message
            )
          return callback(searchErr)
        }

        switch (result.length) {
          case 0:
            return callback()
          case 1:
            return callback(null, result[0])
          default:
            return callback(
              format(
                'unexpected number of matches (%s) for "%s" username',
                result.length,
                username
              )
            )
        }
      }
    )
  })
}

var adUnsafeChars = /[^ a-zA-Z0-9.&\-_[\]`~|@$%^?:{}!']/g
var adSpecialChars = {
  ',': 1,
  '\\': 1,
  '#': 1,
  '+': 1,
  '<': 1,
  '>': 1,
  ';': 1,
  '"': 1,
  '=': 1,
}

ADAuth.prototype._escapeADString = function (str) {
  var hex
  var es = str.replace(adUnsafeChars, function (match) {
    if (adSpecialChars[match]) {
      return '\\' + match
    } else {
      hex = match.charCodeAt(match).toString(16)
      if (hex.length % 2 !== 0) {
        hex = '0' + hex
      }
      return '\\' + hex
    }
  })
  if (es.charAt(0) === ' ') {
    es = '\\20' + (es.length > 1 ? es.substring(1) : '')
  }
  if (es.charAt(es.length - 1) === ' ') {
    es = (es.length > 1 ? es.substring(0, es.length - 1) : '') + '\\20'
  }
  return es
}

ADAuth.prototype._binarySIDToString = function (binarySID) {
  var sid = 'S-' + binarySID[0].toString()
  // eslint-disable-next-line no-bitwise
  var subAuthCount = binarySID[1] & 0xff
  var authority
  for (var i = 2; i <= 7; i++) {
    // eslint-disable-next-line no-bitwise
    authority |= binarySID[i] << (8 * (5 - (i - 2)))
  }
  sid += '-' + authority.toString(16)
  var offset = 8
  var size = 4
  var subAuth
  for (i = 0; i < subAuthCount; i++) {
    subAuth = Long.fromNumber(0)
    for (var j = 0; j < size; j++) {
      subAuth = subAuth.or(
        // eslint-disable-next-line no-bitwise
        Long.fromNumber(binarySID[offset + j] & 0xff).shiftLeft(8 * j)
      )
    }
    sid += '-' + subAuth.toString()
    offset += size
  }
  return sid
}

ADAuth.prototype._binaryGUIDToString = function (binaryGUID) {
  var guid = '{'
  var idx
  for (var i = 0; i < binaryGUID.length; i++) {
    if (i < 4) {
      idx = 3 - i
    } else if (i === 4 || i === 6) {
      idx = i + 1
    } else if (i === 5 || i === 7) {
      idx = i - 1
    } else {
      idx = i
    }
    guid +=
      (binaryGUID[idx] < 0x10 ? '0' : '') +
      binaryGUID[idx].toString(16) +
      (i === 3 || i === 5 || i === 7 || i === 9 ? '-' : '')
  }
  return guid + '}'
}

ADAuth.prototype._findObjectBySID = function (sid, options, callback) {
  var self = this
  var findSID =
    typeof sid !== 'string' && Array.isArray(sid)
      ? self._binarySIDToString(sid)
      : sid
  var opts = {
    filter: format('(objectSid=%s)', findSID),
    scope: self.opts.groupSearchScope,
    userClient: options.userClient,
  }

  self._search(
    options.baseDn || self.opts.domainDn,
    opts,
    function (err, result) {
      if (err) {
        self.log &&
          self.log.trace(
            'find object by sid: search error: %s %s %s',
            err.code,
            err.name,
            err.message
          )
        return callback(err)
      }

      callback(null, result && result[0])
    }
  )
}

/**
 * Find groups for given user
 *
 * @private
 * @param {Object} user - The LDAP user object
 * @param {Object} options LDAP search options
 * @param {string} options.filter - LDAP search filter
 * @param {string} options.scope - LDAP search scope
 * @param {(string[]|undefined)} options.attributes - Attributes to fetch
 * @param {resultCallback} callback - Result handling callback
 * @returns {undefined}
 */
ADAuth.prototype._findGroups = function (user, options, callback) {
  var self = this
  if (!user) {
    return callback(new Error('no user'))
  }
  var opts = options || {}
  var objGroups = []
  var resolved = []

  // Recursively fetch effective group membership because AD's recursive group
  // membership filter is insanely slow (running 20 separate queries through
  // this method is 5-10x faster than a single query using the filter).
  var resolve = function (obj, done) {
    if (!obj) {
      return done(
        new Error('AD authenticate: Cannot find groups for undefined object')
      )
    }

    var searchFilter = self.opts.groupSearchFilter.replace(
      /{{dn}}/g,
      obj[self.opts.groupDnProperty]
    )
    var searchOpts = {
      filter: searchFilter,
      scope: self.opts.groupSearchScope,
      userClient: opts.userClient,
      baseDn: self.opts.groupSearchBase,
    }
    if (self.opts.groupSearchAttributes) {
      searchOpts.attributes = self.opts.groupSearchAttributes
    }
    self._search(self.opts.groupSearchBase, searchOpts, function (err, result) {
      if (err) {
        self.log &&
          self.log.trace(
            'AD authenticate: group search error: %s %s %s',
            err.code,
            err.name,
            err.message
          )
        return done(err)
      }

      var groups = result

      var iterateGroups = function () {
        var needResolution = []

        for (var i = 0; i < result.length; i++) {
          if (resolved.indexOf(result[i].objectSid) === -1) {
            resolved.push(result[i].objectSid)
            needResolution.push(result[i])
            objGroups.push(result[i])
          }
        }

        var toResolve = needResolution.length

        if (!toResolve) {
          done(null)
        }

        needResolution.forEach(function (group) {
          resolve(group, function (resolveErr) {
            if (resolveErr) {
              self._handleError(resolveErr)
            }
            if (!--toResolve) {
              done(null)
            }
          })
        })
      }

      // Primary group is not returned by group membership query. Instead, the
      // SID for the group must be determined based on objectSID and the
      // primaryGroupID, and then queried against the directory.
      if (obj.primaryGroupID) {
        var primaryGroupSID =
          obj.objectSid.substring(0, obj.objectSid.lastIndexOf('-') + 1) +
          obj.primaryGroupID

        self._findObjectBySID(
          primaryGroupSID,
          searchOpts,
          function (findErr, primaryGroup) {
            if (findErr) {
              self.log &&
                self.log.trace(
                  'find primary group by SID: search error %s %s %s',
                  findErr.code,
                  findErr.name,
                  findErr.message
                )
              return done(findErr)
            }

            if (primaryGroup) {
              groups.unshift(primaryGroup)
              if (Array.isArray(obj.memberOf)) {
                obj.memberOf.unshift(primaryGroup.dn)
              } else if (obj.memberOf) {
                obj.memberOf = [primaryGroup.dn, obj.memberOf]
              }
            }

            iterateGroups()
          }
        )
      } else {
        iterateGroups()
      }
    })
  }
  resolve(user, function (err) {
    if (err) {
      self.log &&
        self.log.trace(
          'AD authenticate: group search error: %s %s %s',
          err.code,
          err.name,
          err.message
        )
      return callback(err)
    }
    user._groups = objGroups
    callback(null, user)
  })
}

/**
 * Authenticate given credentials against AD server
 *
 * @param {string} username - The username to authenticate
 * @param {string} password - The password to verify
 * @param {resultCallback} callback - Result handling callback
 * @returns {undefined}
 */
ADAuth.prototype.authenticate = function (username, password, callback) {
  var self = this

  if (typeof password === 'undefined' || password === null || password === '') {
    return callback(new Error('no password given'))
  }

  if (self.opts.cache) {
    // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
    var cached = self.userCache.get(username)
    if (cached && bcrypt.compareSync(password, cached.password)) {
      return callback(null, cached.user)
    }
  }

  // 1. Attempt to bind with the give credentials to validate them
  //
  // We are authenticating first so that AD can log failed signin attempts,
  // apply necessary user lockout policies, and so that it is harder to run
  // a list of usernames against the AD domain controller to see which ones
  // exist based on response time (binding causes an unavoidable delay).
  self._userClient.bind(username, password, function (bindErr) {
    if (bindErr) {
      self.log && self.log.trace('AD authenticate: bind error: %s', bindErr)
      return callback(bindErr)
    }
    var opts = {
      userClient: self._userClient,
    }
    // 2. Find the user DN in question.
    self._findUser(username, opts, function (findErr, user) {
      if (findErr) {
        return callback(findErr)
      }
      if (!user) {
        return callback(format('no such user: "%s"', username))
      }
      // 3. Fetch user groups
      self._getGroups(user, opts, function (groupErr, userWithGroups) {
        if (groupErr) {
          self.log &&
            self.log.trace('AD authenticate: group search error %s', groupErr)
          return callback(groupErr)
        }
        if (self.opts.cache) {
          bcrypt.hash(password, self._salt, function (err, hash) {
            if (err) {
              self.log &&
                self.log.trace(
                  'AD authenticate: bcrypt error, not caching %s',
                  err
                )
            } else {
              self.userCache.set(username, {
                password: hash,
                user: userWithGroups,
              })
            }
            return callback(null, userWithGroups)
          })
        } else {
          return callback(null, userWithGroups)
        }
      })
    })
  })
}

module.exports = ADAuth
