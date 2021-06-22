import EventEmitter from 'events'
import ldapjs from 'ldapjs'
import ADAuth from '../../lib/adauth'
import ADDumpReader from './ad-dump-reader'
import MockLdapSearchResponse from './ldap-search-response'

export default class MockLdapClient extends EventEmitter {
  #lastMessageID = 1

  #dumpReader: ADDumpReader

  get #messageID(): number {
    return this.#lastMessageID++
  }

  constructor({ url }: ADAuth.Options, dumpReader: ADDumpReader) {
    super()

    if (!dumpReader.optionsMatchDump(url)) {
      throw new Error('Options passed to client do not match dump.')
    }
    this.#dumpReader = dumpReader
  }

  bind(
    username: string,
    password: string,
    callback: (error?: Error) => void
  ): void {
    const response = this.#dumpReader.getBindResponse(username, password)
    return callback(response.error)
  }

  search(
    base: string,
    options: ldapjs.SearchOptions,
    callback: (error?: Error, result?: any) => void
  ): void {
    const response = this.#dumpReader.getSearchResponse(base, options)
    return callback(
      response.error,
      response.error
        ? undefined
        : new MockLdapSearchResponse(
            this.#messageID,
            this.#dumpReader.getSearchResults(base, options)
          )
    )
  }

  unbind(callback: (error?: Error) => void): void {
    callback(this.#dumpReader.getUnbindResponse()?.error)
  }

  destroy(): void {
    return
  }
}
