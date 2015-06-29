# Change log

## 0.1.4
### Fixed
- `objectGUID` attributes are now serialized correctly. Prior, they would be
  serialized into unusable strings, such as `{----------------}`.

## 0.1.3
### Added
- Support for loading CA certificates for AD off of the file system or a web
  server.

## 0.1.2
### Added
- `objectGUID` attributes on objects are now converted to a human-readable
  string format

## 0.1.1
### Fixed
- Unhandled case where `user.memberOf` may be a string object instead of an
  array, leading to an error when `memberOf.unshift` is attempted

## 0.1.0
First working version after being forked from node-ldapauth-fork

### Added
- New, required, configuration property `domainDn`, which points to the
  distinguished name of the domain root (e.g. `dc=corp,dc=example,dc=com`)
- `searchFilterByDN` configuration property, which defaults to
  `(&(objectCategory=user)(objectClass=user)(distinguishedName={{dn}}))`
- `searchFilterByUPN` configuration property, which defaults to
  `(&(objectCategory=user)(objectClass=user)(userPrincipalName={{upn}}))`
- `searchFilterBySAN` configuration property, which defaults to
  `(&(objectCategory=user)(objectClass=user)(samAccountName={{username}}))`
- Users can now be authenticated both by their user principal name, or UPN,
  (`user@example.com`) and down-level logon name (`EXAMPLE\user`)
- A user's `primaryGroupID` is now used to resolve the primary group object and
  prepend it to `memberOf` and `_groups`
- Group membership is now fetched recursively and represents all the groups a
  user is an _effective_ member of

### Removed
- `searchFilter` configuration property, which has has been split into
  `searchFilterByDN`, `searchFilterByUPN`, and `searchFilterBySAN`
- `cutarelease.py` build step, in favour of a manual release workflow. This may
  be reconsidered at a later time.

### Changed
- The authentication process now attempts to bind the user's credentials first.
  Subsequent LDAP queries use the client bound to the user's credentials
- Groups are now fetched by default instead of on-demand
- `searchBase` now defaults to the value of `domainDn` and isn't required to be
  explicitly set
- `groupSearchFilter` now defaults to
  `(&(objectCategory=group)(objectClass=group)(member={{dn}}))`
- Dependency versions now use caret (`^`), except for `ldapjs`, which refers to
  `master`, pending a future release
