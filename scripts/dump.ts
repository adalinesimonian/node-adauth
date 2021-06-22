/* eslint-disable no-process-exit */
import { exec } from 'child_process'
import { promises as fs } from 'fs'
import path from 'path'
import ldapjs from 'ldapjs'
import stringify from 'fast-json-stable-stringify'
import ADAuth from '../lib/adauth'
import {
  runADTest,
  adURL,
  adDomainDN,
  adUsername,
  adCredentials,
} from '../tests/integration/env'
import { ADDump, ADDumpEmptyResponse } from '../tests/mocks/ad-dump-reader'

if (!runADTest) {
  console.error(
    'Connection parameters not provided. Either environment variables need ' +
      'to be provided, or test.config.js must be configured in the project root.'
  )
  process.exit(1)
}

let auth: ADAuth

const searchCalls = new Map<number, any>()
const resultsBySearchArgs = new Map<
  string,
  { entries: any[]; end: any; error?: Error }
>()
const emittedErrors: { time: number; error: Error }[] = []
const bindResponses = new Map<string, Map<string, ADDumpEmptyResponse>>()
let unbindResponse: ADDumpEmptyResponse
let timeoutResponse: ADDumpEmptyResponse

let startTime: number

const getResultForSearchArgs = (
  searchArgs: [searchBase: string, searchOptions: ldapjs.SearchOptions]
) => {
  const argKey = stringify(searchArgs)
  const existing = resultsBySearchArgs.get(argKey)
  if (existing) {
    return existing
  }

  const result = {
    entries: [],
    end: undefined,
    error: undefined,
  }
  resultsBySearchArgs.set(argKey, result)
  return result
}

const addEntry = (
  searchArgs: [searchBase: string, searchOptions: ldapjs.SearchOptions],
  entry
) => {
  const { entries } = getResultForSearchArgs(searchArgs)

  if (entries.length === 0 || entries[0].messageID === entry.messageID) {
    entries.push(entry)
  }
}

const addBindResponse = (username, password, error) => {
  const existingPasswords = bindResponses.get(username)
  if (existingPasswords) {
    existingPasswords.set(password, { error })
    return
  }

  bindResponses.set(username, new Map([[password, { error }]]))
}

const addToMapArray = <K, V>(map: Map<K, V[]>, key: K, value: V) => {
  const existing = map.get(key)
  if (existing) {
    existing.push(value)
    return
  }
  map.set(key, [value])
}

const mapToObject = <K extends string | number | symbol, V>(
  map: Map<K, V>
): Record<K, V> => {
  const obj = {} as Record<K, V>
  for (const [key, value] of map) {
    obj[key] = value instanceof Map ? mapToObject(value) : value
  }
  return obj
}

const newAuth = (connectTimeout?: number) => {
  const adAuth = new ADAuth({
    url: adURL,
    domainDN: adDomainDN,
    cache: true,
    debug: true,
    connectTimeout,
  })

  adAuth.on('debug', debug => {
    const { event, data, call, arguments: args, error, resolve } = debug
    if (event) {
      const { searchArgs, entry, result, error: eventError } = data
      switch (event) {
        case 'error':
          emittedErrors.push({
            time: new Date().getTime() - startTime,
            error: eventError,
          })
          return
        case 'connectTimeout':
          timeoutResponse = { error: eventError }
          return
        case 'searchResult.searchEntry':
          addEntry(searchArgs, entry)
          return
        case 'searchResult.error':
          getResultForSearchArgs(searchArgs).error = eventError
          return
        case 'searchResult.end':
          getResultForSearchArgs(searchArgs).end = result
          return
        default:
          console.log(`WARNING: Unknown debug event emitted: ${event}`, debug)
          return
      }
    }
    if (call) {
      switch (call) {
        case 'bind':
          addBindResponse(args[0], args[1], error)
          return
        case 'unbind':
          unbindResponse = { error }
          return
        case 'destroy':
          return
        case 'search':
          addToMapArray(searchCalls, new Date().getTime() - startTime, {
            args,
            error,
            resolve,
          })
          return
        default:
          console.log(`WARNING: Unknown debug call emitted: ${call}`, debug)
          return
      }
    }
    console.dir(data)
  })

  return adAuth
}

const runAuth = async () => {
  auth = newAuth()
  startTime = new Date().getTime()

  await auth.initialise()
  await auth.authenticate(adUsername, adCredentials)
  await auth.dispose()

  auth = newAuth()
  startTime = new Date().getTime()

  await auth.initialise()
  try {
    await auth.authenticate('INVALID_USERNAME', 'INVALID_CREDENTIALS')
    // eslint-disable-next-line no-empty
  } catch {}
  await auth.dispose()

  auth = newAuth(1)
  startTime = new Date().getTime()

  await auth.initialise()
  await auth.dispose()
}

const serialize = () => {
  const invalidCredentialsBind = bindResponses
    .get('INVALID_USERNAME')
    ?.get('INVALID_CREDENTIALS')

  const validCredentialsBindMap = new Map(bindResponses)
  validCredentialsBindMap.delete('INVALID_USERNAME')

  const validCredentialsBind: {
    username: string
    credentials: string
    response: { error?: Error }
  }[] = []
  for (const [username, passwordMap] of validCredentialsBindMap) {
    for (const [credentials, response] of passwordMap) {
      validCredentialsBind.push({
        username,
        credentials,
        response,
      })
    }
  }

  const searchMap = new Map<
    string,
    { time: number; error?: Error; resolve: any }
  >()
  for (const [time, calls] of searchCalls) {
    for (const { args, error, resolve } of calls) {
      searchMap.set(stringify(args), { time, error, resolve })
    }
  }

  return {
    config: {
      url: adURL,
      domainDN: adDomainDN,
      username: adUsername,
      credentials: adCredentials,
    },
    responses: {
      timeout: timeoutResponse,
      bind: {
        invalidCredentials: invalidCredentialsBind,
        validCredentials: validCredentialsBind,
      },
      unbind: unbindResponse,
      errors: emittedErrors,
      search: mapToObject(searchMap),
    },
    searchResults: mapToObject(resultsBySearchArgs),
  } as ADDump
}

;(async () => {
  await runAuth()
  const serialized = JSON.stringify(serialize())
  const dumpPath = path.join(__dirname, '../tests/mocks/dump.json')
  await fs.writeFile(dumpPath, serialized)
  exec(`yarn format:prettier "${dumpPath}"`)
})()
