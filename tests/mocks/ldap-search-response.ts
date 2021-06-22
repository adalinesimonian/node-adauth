import EventEmitter from 'events'
import { ADDumpSearchResult } from './ad-dump-reader'

export default class MockLdapSearchResponse extends EventEmitter {
  #messageID: number
  #entries: any[]
  #endResponse: any
  constructor(messageID: number, result: ADDumpSearchResult) {
    super()

    this.#messageID = messageID
    this.#entries = result.entries
    this.#endResponse = result.end
  }

  listenerMap = new Map()

  on(event: string | symbol, listener: (...args: any[]) => void): this {
    this.listenerMap.set(event, listener)
    const entryListener = this.listenerMap.get('searchEntry')
    const endListener = this.listenerMap.get('end')
    if (
      entryListener &&
      endListener &&
      (event === 'searchEntry' || event === 'end')
    ) {
      for (const entry of this.#entries) {
        entryListener(Object.assign({}, entry, { messageID: this.#messageID }))
      }
      if (endListener) {
        endListener(this.#endResponse)
      }
    }
    return this
  }
}
