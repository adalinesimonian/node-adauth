import ADAuth from '../../../lib/adauth'

describe('Using constructor', () => {
  test('Throws with missing options', () => {
    expect(() => new (ADAuth as any)()).toThrowErrorMatchingSnapshot()
  })

  test('Throws with missing URL', () => {
    expect(
      () =>
        new ADAuth({
          domainDN: 'dc=example,dc=com',
        } as any)
    ).toThrowErrorMatchingSnapshot()
  })

  test('Throws with missing domain DN', () => {
    expect(
      () =>
        new ADAuth({
          url: 'ldap://ldap.forumsys.com:389',
        } as any)
    ).toThrowErrorMatchingSnapshot()
  })

  test('Creates instance with valid options', () => {
    expect(
      new ADAuth({
        url: 'ldap://ldap.forumsys.com:389',
        domainDN: 'dc=example,dc=com',
      })
    ).toBeInstanceOf(ADAuth)
  })
})

describe('Using static create method', () => {
  test('Rejects with missing options', () => {
    expect((ADAuth as any).create()).rejects.toMatchSnapshot()
  })

  test('Rejects with missing URL', () => {
    expect(
      ADAuth.create({
        domainDN: 'dc=example,dc=com',
      } as any)
    ).rejects.toMatchSnapshot()
  })

  test('Rejects with missing domain DN', () => {
    expect(
      ADAuth.create({
        url: 'ldap://ldap.forumsys.com:389',
      } as any)
    ).rejects.toMatchSnapshot()
  })

  test('Creates instance with valid options', async () => {
    const auth = await ADAuth.create({
      url: 'ldap://ldap.forumsys.com:389',
      domainDN: 'dc=example,dc=com',
    })
    expect(auth).toBeInstanceOf(ADAuth)
    await auth.dispose()
  })
})
