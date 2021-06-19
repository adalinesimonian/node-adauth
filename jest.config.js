/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path')
const { runADTest } = require(path.join(__dirname, 'tests/integration/env'))

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns: [
    '/node_modules/',
    ...(runADTest
      ? []
      : ['<rootDir>/tests/integration/__tests__/ad-authenticate.ts']),
  ],
}
