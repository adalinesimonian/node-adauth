const {
  TEST_AD_URL,
  TEST_AD_DOMAIN_DN,
  TEST_AD_USERNAME,
  TEST_AD_CREDENTIALS,
  INTEGRATION_TESTS,
} = process.env

let configured = {}

try {
  // eslint-disable-next-line global-require
  configured = require('../../test.config.js')
  // eslint-disable-next-line no-empty
} catch {}

/**
 * @template T, U
 * @param {T} target
 * @param {U} source
 * @returns {T & U}
 */
const assignDefined = (target, source) => {
  const descriptors = Object.getOwnPropertyDescriptors(source)
  for (const key of Object.getOwnPropertyNames(descriptors)) {
    const descriptor = descriptors[key]
    if (
      !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
      descriptor.value !== undefined
    ) {
      Object.defineProperty(target, key, descriptor)
    }
  }
  return target
}

module.exports = assignDefined(configured, {
  adURL: TEST_AD_URL,
  adDomainDN: TEST_AD_DOMAIN_DN,
  adUsername: TEST_AD_USERNAME,
  adCredentials: TEST_AD_CREDENTIALS,
  get runADTest() {
    return (
      this.adURL && this.adDomainDN && this.adUsername && this.adCredentials
    )
  },
  runIntegrationTests: Boolean(INTEGRATION_TESTS),
})
