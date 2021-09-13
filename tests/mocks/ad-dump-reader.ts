import fs from 'fs'
import path from 'path'
import stringify from 'fast-json-stable-stringify'
import ldapjs from 'ldapjs'
import { LDAPError } from 'ldapjs/lib/errors'

export interface ADDumpConfig {
  url: string
  domainDN: string
  username: string
  credentials: string
}

export interface ADDumpSearchResult {
  entries: any[]
  end: any
  error?: Error
}

export interface ADDumpResponse {
  error?: Error
  resolve: any
}

export interface ADDumpEmptyResponse {
  error?: Error
}

export interface ADDump {
  config: ADDumpConfig
  responses: {
    timeout: ADDumpEmptyResponse
    bind: {
      invalidCredentials: ADDumpEmptyResponse
      validCredentials: {
        username: string
        credentials: string
        response: ADDumpEmptyResponse
      }[]
    }
    unbind: ADDumpEmptyResponse
    errors: { time: number; error: Error }[]
    search: {
      [argumentsKey: string]: ADDumpResponse
    }
  }
  searchResults: {
    [argumentsKey: string]: ADDumpSearchResult
  }
}

const sanitize = (obj: any) => {
  if (!obj) {
    return obj
  }
  if (typeof obj === 'string' || typeof obj === 'number') {
    return obj
  }
  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return Buffer.from(obj.data)
  }
  if (obj['lde_message'] || obj['lde_dn']) {
    return new LDAPError(obj['lde_message'], obj['lde_dn'])
  }
  if (Array.isArray(obj)) {
    return obj.map(element => sanitize(element))
  }
  const newObj = {}
  for (const key of Object.getOwnPropertyNames(obj)) {
    newObj[key] = sanitize(obj[key])
  }
  return newObj
}

const urlMatches = (url1: URL, url2: URL): boolean => {
  if (url1.protocol !== url2.protocol || url1.host !== url2.host) {
    return false
  }

  const url1Pathname = url1.pathname === '' ? '/' : url1.pathname
  const url2Pathname = url2.pathname === '' ? '/' : url2.pathname

  return (
    path.posix.normalize(url1Pathname) === path.posix.normalize(url2Pathname)
  )
}

export default class ADDumpReader {
  #dump: ADDump

  constructor(jsonPath: string = path.join(__dirname, 'dump.json')) {
    const raw = fs.readFileSync(jsonPath, 'utf8')
    this.#dump = sanitize(JSON.parse(raw))
  }

  getConfig(): ADDumpConfig {
    return Object.assign({}, this.#dump.config)
  }

  optionsMatchDump(url: string | string[]): boolean {
    if (Array.isArray(url)) {
      return false
    }

    const { config } = this.#dump

    try {
      return urlMatches(new URL(url), new URL(config.url))
    } catch {
      return false
    }
  }

  getTimeoutResponse(): ADDumpEmptyResponse {
    return this.#dump.responses.timeout
  }

  getBindResponse(username: string, credentials: string): ADDumpEmptyResponse {
    const { validCredentials, invalidCredentials } = this.#dump.responses.bind

    const validResponse = validCredentials.find(
      ({ username: knownUsername, credentials: knownCredentials }) =>
        username === knownUsername && credentials === knownCredentials
    )
    if (validResponse) {
      return validResponse.response
    }

    return invalidCredentials
  }

  getUnbindResponse(): ADDumpEmptyResponse {
    return this.#dump.responses.unbind
  }

  getSearchResponse(
    searchBase: string,
    searchOptions: ldapjs.SearchOptions
  ): ADDumpResponse {
    return this.#dump.responses.search[stringify([searchBase, searchOptions])]
  }

  getSearchResults(
    searchBase: string,
    searchOptions: ldapjs.SearchOptions
  ): ADDumpSearchResult {
    const { searchResults } = this.#dump

    const result = searchResults[stringify([searchBase, searchOptions])]
    if (result) {
      return result
    }

    const end = searchResults[Object.getOwnPropertyNames(searchResults)[0]].end

    return {
      entries: [],
      end,
      error: undefined,
    }
  }
}
