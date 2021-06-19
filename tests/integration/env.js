const {
  TEST_AD_URL,
  TEST_AD_DOMAIN_DN,
  TEST_AD_USERNAME,
  TEST_AD_CREDENTIALS,
} = process.env

module.exports = {
  runADTest:
    Boolean(TEST_AD_URL) &&
    Boolean(TEST_AD_DOMAIN_DN) &&
    Boolean(TEST_AD_USERNAME) &&
    Boolean(TEST_AD_CREDENTIALS),
  adURL: TEST_AD_URL,
  adDomainDN: TEST_AD_DOMAIN_DN,
  adUsername: TEST_AD_USERNAME,
  adCredentials: TEST_AD_CREDENTIALS,
}
