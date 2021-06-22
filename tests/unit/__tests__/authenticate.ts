import ADAuth from '../../../lib/adauth'
import ldapjs from 'ldapjs'
import MockLdapClient from '../../mocks/ldap-client'
import ADDumpReader from '../../mocks/ad-dump-reader'

const dumpReader = new ADDumpReader()
const dumpConfig = dumpReader.getConfig()

jest.mock('ldapjs', () => ({
  createClient: jest.fn(options => new MockLdapClient(options, dumpReader)),
}))

const ldap = ldapjs as jest.Mocked<typeof ldapjs>

let auth: ADAuth

beforeEach(async () => {
  ldap.createClient.mockClear()
  auth = await ADAuth.create({
    url: dumpConfig.url,
    domainDN: dumpConfig.domainDN,
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

describe('With valid credentials', () => {
  test('Authenticates', async () => {
    const user = await auth.authenticate(
      dumpConfig.username,
      dumpConfig.credentials
    )
    expect(user).toBeTruthy()
    expect(user).toMatchSnapshot()
  })

  test('Re-authenticates', async () => {
    const user1 = await auth.authenticate(
      dumpConfig.username,
      dumpConfig.credentials
    )
    expect(user1).toBeTruthy()
    const user2 = await auth.authenticate(
      dumpConfig.username,
      dumpConfig.credentials
    )
    expect(user2).toBeTruthy()
    expect(user1).toEqual(user2)
    expect(user1).toMatchSnapshot()
  })
})

describe('With invalid credentials', () => {
  test('Fails authentication', async () => {
    return expect(
      auth.authenticate('INVALID_USERNAME', 'INVALID_CREDENTIALS')
    ).rejects.toMatchSnapshot()
  })
})
