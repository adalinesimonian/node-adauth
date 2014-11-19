Fork of [node-ldapauth](https://github.com/trentm/node-ldapauth) - A simple node.js lib to authenticate against an LDAP server.

## About the fork

This fork was created and published because of an urgent need to get newer
version of [ldapjs](http://ldapjs.org/) in use to
[passport-ldapauth](https://github.com/vesse/passport-ldapauth) since the newer
version supports passing `tlsOptions` to the TLS module. Once the original
module is updated I will likely deprecate the fork.

Changes in this fork include:

* ldapjs upgraded from 0.5.6 to 0.6.3 ([#11](https://github.com/trentm/node-ldapauth/issues/11), [#12](https://github.com/trentm/node-ldapauth/issues/12))
* use global search/replace of `{{username}}` ([#10](https://github.com/trentm/node-ldapauth/issues/10))
* enable defining timeouts ([#12](https://github.com/trentm/node-ldapauth/issues/12))
* enable defining attributes to return from LDAP server ([#8](https://github.com/trentm/node-ldapauth/issues/10))
* enable anonymous binding ([#2](https://github.com/trentm/node-ldapauth/issues/2))
* enable defining seach scope
* clients are unbound in `close()` ([#3](https://github.com/trentm/node-ldapauth/issues/3))
* `bcrypt` is an optional dependency ([#13](https://github.com/trentm/node-ldapauth/pull/13), also affects [#9](https://github.com/trentm/node-ldapauth/issues/9))

Multiple [ldapjs](http://ldapjs.org/) client options have been made available. From the original options `adminDn` and `adminPassword` are optional.

## Usage

    var LdapAuth = require('ldapauth-fork');
    var options = {
        url: 'ldaps://ldap.example.com:663',
        ...
    };
    var auth = new LdapAuth(options);
    ...
    auth.authenticate(username, password, function(err, user) { ... });
    ...
    auth.close(function(err) { ... })


## Install

    npm install ldapauth-fork


## License

MIT. See "LICENSE" file.


## `LdapAuth` Config Options

[Use the source Luke](https://github.com/vesse/node-ldapauth-fork/blob/master/lib/ldapauth.js#L25-76)


## express/connect basicAuth example

    var connect = require('connect');
    var LdapAuth = require('ldapauth-fork');

    // Config from a .json or .ini file or whatever.
    var config = {
      ldap: {
        url: "ldaps://ldap.example.com:636",
        bindDn: "uid=myadminusername,ou=users,o=example.com",
        bindCredentials: "mypassword",
        searchBase: "ou=users,o=example.com",
        searchFilter: "(uid={{username}})"
      }
    };

    var ldap = new LdapAuth({
      url: config.ldap.url,
      bindDn: config.ldap.bindDn,
      bindCredentials: config.ldap.bindCredentials,
      searchBase: config.ldap.searchBase,
      searchFilter: config.ldap.searchFilter,
      //log4js: require('log4js'),
      cache: true
    });

    var basicAuthMiddleware = connect.basicAuth(function (username, password, callback) {
      ldap.authenticate(username, password, function (err, user) {
        if (err) {
          console.log("LDAP auth error: %s", err);
        }
        callback(err, user)
      });
    });
