/* eslint-disable @typescript-eslint/no-var-requires */
const { runADTest, runIntegrationTests } = require('./tests/integration/env')

const testPathIgnorePatterns = ['/node_modules/']

if (!runIntegrationTests) {
  testPathIgnorePatterns.push('<rootDir>/tests/integration/')
} else if (!runADTest) {
  testPathIgnorePatterns.push(
    '<rootDir>/tests/integration/__tests__/ad-authenticate.ts'
  )
}

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns,
}
