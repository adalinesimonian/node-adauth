# Contributing to node-adauth

To get up and running, install the dependencies and run the tests:

```bash
yarn
yarn test
```

## Tests

Some of the tests use [Jest snapshots](https://facebook.github.io/jest/docs/en/snapshot-testing.html). You can make changes and run `jest -u` (or `yarn test -u`) to update the snapshots. Then run `git diff` to take a look at what changed. Always update the snapshots when opening a PR.

### Authentication unit test

The authentication unit test relies on data dumped from a live AD instance. This data, which lives in `tests/mocks/dump.json`, can be updated using `yarn dump`. The dump script requires the connection to the AD server to be configured either using environment variables or a config file (see [the Integration tests](#Integration_tests) section for more details).

Generally, this dump shouldn't need any updates. However, it may if the internals of node-adauth have significantly changed. If you must update it, make sure unit tests still pass afterwards.

### Integration tests

There are several integration tests:

- An LDAP test, which uses a public LDAP server for testing.
- An Active Directory test, which requires configuring the AD server to connect to.

These integration tests can be run along with the main test run by specifying the `INTEGRATION_TESTS` environment variable with a truthy value (e.g. `true` or `1`). Additionally, you can run the integration tests separately using `yarn test:integration`.

The AD test can be configured using the following environment variables:

- `TEST_AD_URL` — LDAP URL pointing to the AD server, e.g. `ldap://localhost:389`
- `TEST_AD_DOMAIN_DN` — Domain DN, e.g. `DC=adtest,DC=local`
- `TEST_AD_USERNAME` — Valid username to test authentication with
- `TEST_AD_CREDENTIALS` — Valid password to test authentication with

The test will only run if all four values are provided.

Alternatively, you can create a `test.config.js` file in the project root and configure the connection there:

```js
module.exports = {
  adURL: 'ldap://localhost:389',
  adDomainDN: 'DC=adtest,DC=local',
  adUsername: 'tuser@adtest.local',
  adCredentials: 'Password123',
}
```

> **Note:** Environment variables take precedence over values set in `test.config.js`.

## Formatting/Linting

The project uses ESLint for linting and Prettier for formatting. If your editor isn't set up to work with them, you can lint and format all files from the command line using `yarn format`.
