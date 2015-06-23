## node-adauth

Fork of [node-ldapauth-fork](https://github.com/vesse/node-ldapauth-fork)
targeted towards use with an Active Directory domain.

## Usage

```javascript
var ADAuth = require('adauth');
var options = {
    url: 'ldaps://corp.example.com:636',
    domainDn: 'dc=example,dc=com'
};
var auth = new ADAuth(options);
auth.authenticate(username, password, function(err, user) { ... });
auth.close(function(err) { ... })
```

## Install

    $ npm install adauth


## License

MIT. See "LICENSE" file.


## Configuration

[Use the source Luke](
https://github.com/vsimonian/node-adauth/blob/master/lib/adauth.js#L25-110)


## express/connect basicAuth example

```javascript
var connect = require('connect');
var ADAuth = require('adauth');

// Config from a .json or .ini file or whatever.
var config = {
  ad: {
    url: "ldaps://corp.example.com:636",
    bindDn: "CN=LDAP User,OU=Users,OU=MyBusiness,DC=example,DC=com",
    bindCredentials: "mypassword",
    searchBase: "OU=Users,OU=MyBusiness,DC=example,DC=com"
    tlsOptions: {
      ca: "./example-ca.cer"
    }
  }
};

var ad = new ADAuth(config.ad);

var basicAuthMiddleware = connect.basicAuth(
  function (username, password, callback) {
  ad.authenticate(username, password, function (err, user) {
    if (err) {
      console.log("AD auth error: %s", err);
    }
    callback(err, user)
  });
});
```
