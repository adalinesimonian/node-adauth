# node-ldapauth-fork Changelog

## 2.2.8

- [ldapauth issue #2] support anonymous binding
- [ldapauth issue #3] unbind clients in `close()`
- Added option `searchScope`, default to `sub`

## 2.2.7

- Renamed to node-ldapauth-fork

## 2.2.6

- Another readme fix

## 2.2.5

- Readme updated

## 2.2.4

- [ldapauth issues #11, #12] update to ldapjs 0.6.3
- [ldapauth issue #10] use global search/replace for {{username}}
- [ldapauth issue #8] enable defining attributes to fetch from LDAP server

# node-ldapauth Changelog

## 2.2.3 (not yet released)

(nothing yet)


## 2.2.2

- [issue #5] update to bcrypt 0.7.5 (0.7.3 fixes potential mem issues)


## 2.2.1

- Fix a bug where ldapauth `authenticate()` would raise an example on an empty
  username.


## 2.2.0

- Update to latest ldapjs (0.5.6) and other deps.
  Note: This makes ldapauth only work with node >=0.8 (because of internal dep
  in ldapjs 0.5).


## 2.1.0

- Update to ldapjs 0.4 (from 0.3). Crossing fingers that this doesn't cause breakage.


## 2.0.0

- Add `make check` for checking jsstyle.
- [issue #1] Update to bcrypt 0.5. This means increasing the base node from 0.4
  to 0.6, hence the major version bump.


## 1.0.2

First working version.


