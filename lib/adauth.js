/**
 * Copyright 2011 (c) Trent Mick.
 * Copyright 2015 (c) Vartan Simonian
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

var assert = require('assert');
var Long = require('long');
var ldap = require('ldapjs');
var debug = console.warn;
var format = require('util').format;
var bcrypt = require('bcryptjs');
var validUrl = require('valid-url');
var syncRequest = require('sync-request');
var fs = require('fs');

/**
 * Create an AD auth class. Primary usage is the `.authenticate` method.
 *
 * @param opts {Object} Config options. Keys (required, unless says
 *     otherwise) are:
 *   url {String}
 *     LDAP url for the AD domain controller, e.g.
 *     'ldaps://corp.example.com:636'
 *   domainDn {String}
 *     The root DN of the AD domain, e.g. 'dc=corp,dc=example,dc=com'
 *   bindDn {String}
 *     Optional, e.g. 'uid=myapp,ou=users,o=example.com'. Alias: adminDn
 *   bindCredentials {String}
 *     Password for bindDn. Aliases: Credentials, adminPassword
 *   bindProperty {String}
 *     Optional, default 'dn'. Property of user to bind against client
 *     e.g. 'name', 'email'
 *   searchBase {String}
 *     Optional, default is the domain DN. The base DN from which to search
 *     for users by username.
 *     e.g. 'ou=users,o=example.com'
 *   searchScope {String}
 *     Optional, default 'sub'. Scope of the search, one of 'base',
 *     'one', or 'sub'.
 *   searchFilterByDN {String}
 *     Optional, default
 *     '(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))'
 *     Search filter with which to find a user by FQDN.
 *   searchFilterByUPN {String}
 *     Optional, default
 *     '(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))'
 *     Search filter with which to find a user by UPN. (user@domain.com)
 *   searchFilterBySAN {String}
 *     Optional, default
 *     '(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))'
 *     Search filter with which to find a user by their old-format Windows
 *     username.
 *   searchAttributes {Array}
 *     Optional, default all. Array of attributes to fetch from LDAP server.
 *   groupDnProperty {String}
 *     Optional, default 'dn'. The property of user object to use in
 *     '{{dn}}' interpolation of groupSearchFilter.
 *   groupSearchBase {String}
 *     Optional, default is the domain DN. The base DN from which to search
 *     for groups.
 *   groupSearchScope {String}
 *     Optional, default 'sub'.
 *   groupSearchFilter {String}
 *     Optional, default
 *     '(&(objectCategory=group)(objectClass=group)(member={{dn}}))'
 *     LDAP search filter for user groups. The following literals are
 *     interpolated from the found user object: '{{dn}}' the property
 *     configured with groupDnProperty.
 *   groupSearchAttributes {Array}
 *     Optional, default all. Array of attributes to fetch from LDAP server.
 *   log4js {Module}
 *     Optional. The require'd log4js module to use for logging. If given
 *     this will result in TRACE-level logging for adauth.
 *   verbose {Boolean}
 *     Optional, default false. If `log4js` is also given, this will add
 *     TRACE-level logging for ldapjs (quite verbose).
 *   cache {Boolean}
 *     Optional, default false. If true, then up to 100 credentials at a
 *     time will be cached for 5 minutes.
 *   timeout {Integer}
 *     Optional, default Infinity. How long the client should let
 *     operations live for before timing out.
 *   connectTimeout {Integer}
 *     Optional, default is up to the OS. How long the client should wait
 *     before timing out on TCP connections.
 *   tlsOptions {Object}
 *     Additional options passed to the TLS connection layer when
 *     connecting via ldaps://. See
 *     http://nodejs.org/api/tls.html#tls_tls_connect_options_callback
 *     for available options
 *   maxConnections {Integer}
 *     Whether or not to enable connection pooling, and if so, how many to
 *     maintain.
 *   checkInterval {Integer}
 *     How often to schedule health checks for the connection pool.
 *   maxIdleTime {Integer}
 *     How long a client can be idle before health-checking the connection
 *     (subject to the checkInterval frequency)
 *   includeRaw {boolean}
 *     Optional, default false. Set to true to add property '_raw'
 *     containing the original buffers to the returned user object.
 *     Useful when you need to handle binary attributes.
 */
function ADAuth(opts) {
  this.opts = opts;
  assert.ok(opts.url, 'AD domain controller LDAP URL not defined (opts.url)');
  assert.ok(opts.domainDn, 'Domain DN not defined (opts.rootDn)');
  opts.searchBase = opts.searchBase || opts.domainDn;
  opts.groupSearchBase = opts.groupSearchBase || opts.domainDn;
  opts.searchFilterByDN = opts.searchFilterByDN ||
    '(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))';
  opts.searchFilterByUPN = opts.searchFilterByUPN ||
    '(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))';
  opts.searchFilterBySAN = opts.searchFilterBySAN ||
    '(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))';
  opts.groupSearchFilter = opts.groupSearchFilter ||
    '(&(objectCategory=group)(objectClass=group)(member={{dn}}))';

  this.log = opts.log4js && opts.log4js.getLogger('adauth');

  this.opts.searchScope || (this.opts.searchScope = 'sub');
  this.opts.bindProperty || (this.opts.bindProperty = 'dn');
  this.opts.groupSearchScope || (this.opts.groupSearchScope = 'sub');
  this.opts.groupDnProperty || (this.opts.groupDnProperty = 'dn');

  if (opts.cache) {
    var Cache = require('./cache');
    this.userCache = new Cache(100, 300, this.log, 'user');
  }
  
  if (opts.tlsOptions && opts.tlsOptions.ca && typeof (opts.tlsOptions.ca) === 'string') {
    if (validUrl.isWebUri(opts.tlsOptions.ca)) {
      var cert = syncRequest('GET', opts.tlsOptions.ca);
      opts.tlsOptions.ca = cert.getBody();
    } else {
      try {
        opts.tlsOptions.ca = fs.readFileSync(opts.tlsOptions.ca);
      } catch (err) {}
    }
  }

  this.clientOpts = {
    url: opts.url,
    connectTimeout: opts.connectTimeout,
    timeout: opts.timeout,
    tlsOptions: opts.tlsOptions,
    maxConnections: opts.maxConnections,
    bindDn: opts.bindDn || opts.adminDn,
    bindCredentials: opts.bindCredentials ||
                     opts.Credentials ||
                     opts.adminPassword,
    checkInterval: opts.checkInterval,
    maxIdleTime: opts.maxIdleTime
  };

  if (opts.log4js && opts.verbose) {
    this.clientOpts.log4js = opts.log4js;
  }

  this._adminClient = ldap.createClient(this.clientOpts);
  this._adminBound = false;
  this._userClient = ldap.createClient(this.clientOpts);

  if (opts.cache) {
    this._salt = bcrypt.genSaltSync();
  }

  if (opts.groupSearchBase && opts.groupSearchFilter) {
    this._getGroups = this._findGroups;
  } else {
    // Assign an async identity function so there is no need to branch
    // the authenticate function to have cache set up.
    this._getGroups = function (user, callback) {
      return callback(null, user);
    }
  }
};


ADAuth.prototype.close = function (callback) {
  var self = this;
  // It seems to be OK just to call unbind regardless of if the
  // client has been bound (e.g. how ldapjs pool destroy does)
  self._adminClient.unbind(function (err) {
    self._userClient.unbind(callback);
  });
};


/**
 * Ensure that `this._adminClient` is bound.
 */
ADAuth.prototype._adminBind = function (callback) {
  // Anonymous binding
  if (typeof (this.clientOpts.bindDn) === 'undefined' ||
      this.clientOpts.bindDn === null) {
    return callback();
  }
  if (this._adminBound) {
    return callback();
  }
  var self = this;
  this._adminClient.bind(this.clientOpts.bindDn,
    this.clientOpts.bindCredentials,
    function (err) {
    if (err) {
      self.log && self.log.trace('ldap authenticate: bind error: %s', err);
      return callback(err);
    }
    self._adminBound = true;
    return callback();
  });
};

/**
 * Conduct a search using either the user or admin client (admin by default).
 * Used for fetching both user and group information.
 *
 * @param searchBase {String} LDAP search base
 * @param options {Object} LDAP search options
 * @param {Function} `function (err, result)`.
 */
ADAuth.prototype._search = function (searchBase, options, callback) {
  var self = this;

  var bindFunc = options.userClient ? function (callback) {
    callback();
  } : self._adminBind;

  var ldapClient = options.userClient ? options.userClient : self._adminClient;

  bindFunc(function (err) {
    if (err)
      return callback(err);

    ldapClient.search(searchBase, options, function (err, result) {
      if (err)
        return callback(err);

      var items = [];
      result.on('searchEntry', function (entry) {
        var obj = entry.object;
        obj.objectSid = entry.raw.objectSid ?
          self._binarySIDToString(entry.raw.objectSid) : undefined;
        obj.objectGUID = entry.raw.objectGUID ?
          self._binaryGUIDToString(entry.raw.objectGUID) : undefined;
        if (self.opts.includeRaw === true) {
          obj._raw = entry.raw;
        }
        items.push(obj);
      });

      result.on('error', callback);

      result.on('end', function (result) {
        if (result.status !== 0) {
          var err = 'non-zero status from LDAP search: ' + result.status;
          return callback(err);
        }
        return callback(null, items);
      });
    });
  });
};

/**
 * Find the user record for the given username.
 *
 * @param username {String}
 * @param options {Object} LDAP search options
 * @param callback {Function} `function (err, user)`. If no such user is
 *    found but no error processing, then `user` is undefined.
 *
 */
ADAuth.prototype._findUser = function (username, options, callback) {
  var self = this;
  options = options || {};
  if (!username) {
    return callback('empty username');
  }

  var searchFilter, validateQuery = function (cb) {
    cb();
  };

  if (~username.indexOf('\\')) {
    // If using Domain\username form, ensure that Domain is the domain's actual
    // NetBIOS name and not just any arbitrary text
    var splitUsername = username.split('\\');
    var netBIOSDomainName = splitUsername[0];
    var sAMAccountName = splitUsername[1];

    validateQuery = function (cb) {
      var vopts = {
        filter: format('(distinguishedName=%s)', self.opts.domainDn),
        attributes: [ 'msDS-PrincipalName' ],
        scope: self.opts.searchScope,
        userClient: options.userClient
      };

      self._search(self.opts.domainDn, vopts, function (err, domains) {
        var inName = netBIOSDomainName.toUpperCase();
        if (inName.charAt(inName.length - 1) === '\\') {
          inName = inName.substring(0, inName.length - 1);
        }
        var fdName = domains[0]['msDS-PrincipalName'].toUpperCase();
        if (fdName.charAt(fdName.length - 1) === '\\') {
          fdName = fdName.substring(0, fdName.length - 1);
        }
        if (inName === fdName) {
          searchFilter = self.opts.searchFilterBySAN.replace(/{{username}}/g,
            self._escapeADString(sAMAccountName));
          cb();
        } else {
          var errMsg =
            format('cannot find known domain with netBIOS domain name %s',
              netBIOSDomainName);
          self.log && self.log.trace(errMsg);
          cb(new Error(errMsg));
        }
      });
    };
  } else if (~username.indexOf('@')) {
    searchFilter = self.opts.searchFilterByUPN.replace(/{{upn}}/g,
      self._escapeADString(username));
  } else {
    searchFilter = self.opts.searchFilterBySAN.replace(/{{username}}/g,
      self._escapeADString(username));
  }

  validateQuery(function (err) {
    if (err) {
      return callback(err);
    }

    var opts = {
      filter: searchFilter,
      scope: self.opts.searchScope,
      userClient: options.userClient
    };

    if (self.opts.searchAttributes) {
      opts.attributes = self.opts.searchAttributes;
    }

    self._search(self.opts.searchBase, opts, function (err, result) {
      if (err) {
        self.log &&
          self.log.trace('AD authenticate: user search error: %s %s %s',
            err.code, err.name, err.message);
        return callback(err);
      }

      switch (result.length) {
      case 0:
        return callback();
      case 1:
        return callback(null, result[0]);
      default:
        return callback(format(
          'unexpected number of matches (%s) for "%s" username',
          result.length, username));
      }
    });
  });
};

/* JSSTYLED */
var adUnsafeChars = /[^ a-zA-Z0-9.&\-_[\]`~|@$%^?:{}!']/g;
var adSpecialChars =
  { ',': 1, '\\': 1, '#': 1, '+': 1, '<': 1, '>': 1, ';': 1, '"': 1, '=': 1 };

ADAuth.prototype._escapeADString = function (str) {
  var hex, es = str.replace(adUnsafeChars, function (match) {
    if (adSpecialChars[match]) {
      return '\\' + match;
    } else {
      hex = match.charCodeAt(match).toString(16);
      if (hex.length % 2 !== 0) {
        hex = '0' + hex;
      }
      return '\\' + hex;
    }
  });
  if (es.charAt(0) === ' ') {
    es = '\\20' + (es.length > 1 ? es.substring(1) : '');
  }
  if (es.charAt(es.length - 1) === ' ') {
    es = (es.length > 1 ? es.substring(0, es.length - 1) : '') + '\\20';
  }
  return es;
};

ADAuth.prototype._binarySIDToString = function (binarySID) {
  var sid = 'S-' + binarySID[0].toString();
  var subAuthCount = binarySID[1] & 0xFF;
  var authority;
  for (var i = 2; i <= 7; i++) {
    authority |= binarySID[i] << (8 * (5 - (i - 2)));
  }
  sid += '-' + authority.toString(16);
  var offset = 8, size = 4, subAuth;
  for (i = 0; i < subAuthCount; i++) {
    subAuth = Long.fromNumber(0);
    for (var j = 0; j < size; j++) {
      subAuth = subAuth.or(Long.fromNumber(binarySID[offset + j] & 0xFF)
        .shiftLeft(8 * j));
    }
    sid += '-' + subAuth.toString();
    offset += size;
  }
  return sid;
};

ADAuth.prototype._binaryGUIDToString = function (binaryGUID) {
  var guid = '{';
  var idx;
  for (var i = 0; i < binaryGUID.length; i++) {
    if (i < 4) {
      idx = 3 - i;
    } else if (i === 4 || i === 6) {
      idx = i + 1;
    } else if (i === 5 || i === 7) {
      idx = i - 1;
    } else {
      idx = i;
    }
    guid += ((binaryGUID[idx] < 0x10) ? '0' : '') +
            binaryGUID[idx].toString(16) +
            ((i === 3 || i === 5 || i === 7 || i === 9) ? '-' : '');
  }
  return guid + '}';
};

ADAuth.prototype._findObjectBySID = function (sid, options, callback) {
  var self = this;
  if (typeof (sid) !== 'string' && Array.isArray(sid)) {
    sid = self._binarySIDToString(sid);
  }
  var opts = {
    filter: format('(objectSid=%s)', sid),
    scope: self.opts.groupSearchScope,
    userClient: options.userClient
  };

  self._search(options.baseDn || self.opts.domainDn, opts,
    function (err, result) {
    if (err) {
      self.log &&
        self.log.trace('find object by sid: search error: %s %s %s',
          err.code, err.name, err.message);
      return callback(err);
    }

    callback(null, result && result[0]);
  });
};

ADAuth.prototype._findGroups = function (obj, options, callback) {
  var self = this;
  options = options || {};
  var objGroups = [];
  var resolved = [];

  // Recursively fetch effective group membership because AD's recursive group
  // membership filter is insanely slow (running 20 separate queries through
  // this method is 5-10x faster than a single query using the filter).
  var resolve = function (obj, done) {
    if (!obj) {
      return done(
        new Error('AD authenticate: Cannot find groups for undefined object'));
    }

    var searchFilter = self.opts.groupSearchFilter.replace(/{{dn}}/g,
      obj[self.opts.groupDnProperty]);
    var opts = {
      filter: searchFilter,
      scope: self.opts.groupSearchScope,
      userClient: options.userClient,
      baseDn: self.opts.groupSearchBase
    };
    if (self.opts.groupSearchAttributes) {
      opts.attributes = self.opts.groupSearchAttributes;
    }
    self._search(self.opts.groupSearchBase, opts, function (err, result) {
      if (err) {
        self.log &&
          self.log.trace('AD authenticate: group search error: %s %s %s',
            err.code, err.name, err.message);
        return done(err);
      }

      var groups = result;

      var iterateGroups = function () {
          var needResolution = [];

          for (var i = 0; i < result.length; i++) {
            if (!~resolved.indexOf(result[i].objectSid)) {
              resolved.push(result[i].objectSid);
              needResolution.push(result[i]);
              objGroups.push(result[i]);
            }
          }

          var toResolve = needResolution.length;

          if (!toResolve) {
            done(null);
          }

          needResolution.forEach(function (group) {
            resolve(group, function (err) {
              if (!--toResolve) {
                done(null);
              }
            });
          });
      };

      // Primary group is not returned by group membership query. Instead, the
      // SID for the group must be determined based on objectSID and the
      // primaryGroupID, and then queried against the directory.
      if (obj.primaryGroupID) {
        var primaryGroupSID = obj.objectSid.substring(0,
          obj.objectSid.lastIndexOf('-') + 1) + obj.primaryGroupID;

        self._findObjectBySID(primaryGroupSID, opts,
          function (err, primaryGroup) {
          if (err) {
            self.log &&
              self.log.trace('find primary group by SID: search error %s %s %s',
                err.code, err.name, err.message);
            return done(err);
          }

          if (primaryGroup) {
            groups.unshift(primaryGroup);
            if (Array.isArray(obj.memberOf)) {
              obj.memberOf.unshift(primaryGroup.dn);
            } else if (obj.memberOf) {
              obj.memberOf = [ primaryGroup.dn, obj.memberOf ];
            }
          }

          iterateGroups();
        });
      } else {
        iterateGroups();
      }
    });
  };
  resolve(obj, function (err) {
    if (err) {
        self.log &&
          self.log.trace('AD authenticate: group search error: %s %s %s',
            err.code, err.name, err.message);
        return callback(err);
  	}
    obj._groups = objGroups;
    callback(null, obj);
  });
};

/**
 *
 */
ADAuth.prototype.authenticate = function (username, password, callback) {
  var self = this;

  if (self.opts.cache) {
    // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
    var cached = self.userCache.get(username);
    if (cached && bcrypt.compareSync(password, cached.password)) {
      return callback(null, cached.user);
    }
  }

  // 1. Attempt to bind with the give credentials to validate them
  //
  // We are authenticating first so that AD can log failed signin attempts,
  // apply necessary user lockout policies, and so that it is harder to run
  // a list of usernames against the AD domain controller to see which ones
  // exist based on response time (binding causes an unavoidable delay).
  self._userClient.bind(username, password, function (err) {
    if (err) {
      self.log && self.log.trace('AD authenticate: bind error: %s', err);
      return callback(err);
    }
    var opts = {
      userClient: self._userClient
    };
    // 2. Find the user DN in question.
    self._findUser(username, opts, function (err, user) {
      if (err)
        return callback(err);
      if (!user)
        return callback(format('cannot user object for: "%s"', username));
      // 3. Fetch user groups
      self._getGroups(user, opts, function (err, user) {
        if (err) {
          self.log &&
            self.log.trace('AD authenticate: group search error %s', err);
          return callback(err);
        }
        if (self.opts.cache) {
          bcrypt.hash(password, self._salt, function (err, hash) {
            self.userCache.set(username, {password: hash, user: user});
            return callback(null, user);
          });
        } else {
          return callback(null, user);
        }
      });
    });
  });
};



module.exports = ADAuth;
