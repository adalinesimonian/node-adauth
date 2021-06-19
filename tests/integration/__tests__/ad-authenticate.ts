import ADAuth from '../../../lib/adauth'
import { adURL, adDomainDN, adUsername, adCredentials } from '../env'

let auth: ADAuth

beforeEach(async () => {
  auth = await ADAuth.create({
    url: adURL,
    domainDN: adDomainDN,
    cache: true,
  })

  auth.on('error', error => {
    console.warn(error)
    // TODO: auth.close() doesn't do anything here
  })
})

afterEach(async () => {
  await auth.dispose()
})

test('Can authenticate against test AD server', async () => {
  const user = await auth.authenticate(adUsername, adCredentials)
  expect(user).toBeTruthy()
})

test('Can re-authenticate against test AD server', async () => {
  const user1 = await auth.authenticate(adUsername, adCredentials)
  expect(user1).toBeTruthy()
  const user2 = await auth.authenticate(adUsername, adCredentials)
  expect(user2).toBeTruthy()
  expect(user1).toEqual(user2)
})
