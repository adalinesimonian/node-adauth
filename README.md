## node-adauth

Fork of [node-ldapauth-fork](https://github.com/vesse/node-ldapauth-fork) targeted towards use with an Active Directory domain.

## Usage

```javascript
import ADAuth from 'adauth'

const options = {
  url: 'ldaps://corp.example.com:636',
  domainDN: 'dc=example,dc=com',
}

const auth = await ADAuth.create(options)

// or

const auth = new ADAuth(options)
await auth.initialise()

try {
  const user = await auth.authenticate(username, password)
} catch (error) {
  console.error('Authentication failed: ', error)
}

await auth.dispose()
```

`ADAuth` inherits from `EventEmitter`.

## Install

    $ npm install adauth

## `ADAuth` Config Options

Required client options:

- `url` - LLDAP url for the AD domain controller, e.g. `ldaps://corp.example.com:636`
- `domainDN` - The root DN of the AD domain, e.g. `dc=corp,dc=example,dc=com`

## Configuration

- `searchBase` - The base DN from which to search for users by username. E.g. `ou=users,dc=example,dc=com`
- `searchFilterByDN` - Optional, default `(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))`. Search filter with which to find a user by FQDN.
- `searchFilterByUPN` - Optional, default `(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))`. Search filter with which to find a user by UPN. (user@domain.com)
- `searchFilterBySAN` - Optional, default `(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))`. Search filter with which to find a user by their old-format Windows username.
- `searchAttributes` - Optional, default all. Array of attributes to fetch from LDAP server.
- `bindProperty` - Optional, default `dn`. Property of the LDAP user object to use when binding to verify the password. E.g. `name`, `email`
- `searchScope` - Optional, default `sub`. Scope of the search, one of `base`, `one`, or `sub`.

adauth can look for valid user groups too. Related options:

- `groupSearchBase` - Optional. The base DN from which to search for groups. If defined, also `groupSearchFilter` must be defined for the search to work.
- `groupSearchFilter` - Optional. LDAP search filter for groups. Place literal `{{dn}}` in the filter to have it replaced by the property defined with `groupDnProperty` of the found user object. `{{username}}` is also available and will be replaced with the `uid` of the found user. This is useful for example to filter PosixGroups by `memberUid`. Optionally you can also assign a function instead. The found user is passed to the function and it should return a valid search filter for the group search.
- `groupSearchAttributes` - Optional, default all. Array of attributes to fetch from LDAP server.
- `groupDnProperty` - Optional, default `dn`. The property of user object to use in `{{dn}}` interpolation of `groupSearchFilter`.
- `groupSearchScope` - Optional, default `sub`.

Other adauth options:

- `includeRaw` - Optional, default false. Set to true to add property `_raw` containing the original buffers to the returned user object. Useful when you need to handle binary attributes
- `cache` - Optional, default false. If true, then up to 100 credentials at a time will be cached for 5 minutes.
- `log` - Bunyan logger instance, optional. If given this will result in TRACE-level error logging for component:ldapauth. The logger is also passed forward to ldapjs.

Optional ldapjs options, see [ldapjs documentation](https://github.com/mcavage/node-ldapjs/blob/v1.0.1/docs/client.md):

- `tlsOptions` - Needed for TLS connection. See [Node.js documentation](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback)
- `socketPath`
- `timeout`
- `connectTimeout`
- `idleTimeout`
- `strictDN`
- `queueSize`
- `queueTimeout`
- `queueDisable`

## How it works

The AD authentication flow is usually:

1. Bind the client using the given username and credentials to verify the given password
2. Use the client to search for the user by substituting `{{username}}` from the appropriate `searchFilter`
3. Search for the groups of the user

## express/connect basicAuth example

```javascript
import basicAuth from 'basic-auth'
import ADAuth from 'adauth'

const ad = await ADAuth.create({
  url: "ldaps://corp.example.com:636",
  domainDN: "DC=example,DC=com",
  searchBase: "OU=Users,OU=MyBusiness,DC=example,DC=com",
  tlsOptions: {
    ca: "./example-ca.cer",
  },
  reconnect: true,
})

const rejectBasicAuth = res => {
  res.statusCode = 401
  res.setHeader('WWW-Authenticate', 'Basic realm="Example"')
  res.end('Access denied')
}

const basicAuthMiddleware = (req, res, next) => {
  const credentials = basicAuth(req)
  if (!credentials) {
    return rejectBasicAuth(res)
  }

  ad.authenticate(credentials.name, credentials.pass)
    .then(user => {
      req.user = user
      next()
    })
    .catch(error => rejectBasicAuth(res))
  })
}
```

## License

MIT
