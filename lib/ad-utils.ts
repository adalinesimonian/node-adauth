import Long from 'long'

const binarySIDToString = (binarySID: number[] | Buffer): string => {
  let sid = 'S-' + binarySID[0].toString()
  // eslint-disable-next-line no-bitwise
  const subAuthCount = binarySID[1] & 0xff
  let authority
  for (let i = 2; i <= 7; i++) {
    // eslint-disable-next-line no-bitwise
    authority |= binarySID[i] << (8 * (5 - (i - 2)))
  }
  sid += '-' + authority.toString(16)
  let offset = 8
  const size = 4
  let subAuth
  for (let i = 0; i < subAuthCount; i++) {
    subAuth = Long.fromNumber(0)
    for (let j = 0; j < size; j++) {
      subAuth = subAuth.or(
        // eslint-disable-next-line no-bitwise
        Long.fromNumber(binarySID[offset + j] & 0xff).shiftLeft(8 * j)
      )
    }
    sid += '-' + subAuth.toString()
    offset += size
  }
  return sid
}

const binaryGUIDToString = (binaryGUID: number[] | Buffer): string => {
  let guid = '{'
  let idx
  for (let i = 0; i < binaryGUID.length; i++) {
    if (i < 4) {
      idx = 3 - i
    } else if (i === 4 || i === 6) {
      idx = i + 1
    } else if (i === 5 || i === 7) {
      idx = i - 1
    } else {
      idx = i
    }
    guid +=
      (binaryGUID[idx] < 0x10 ? '0' : '') +
      binaryGUID[idx].toString(16) +
      (i === 3 || i === 5 || i === 7 || i === 9 ? '-' : '')
  }
  return guid + '}'
}

const adUnsafeChars = /[^ a-zA-Z0-9.&\-_[\]`~|@$%^?:{}!']/g
const adSpecialChars = new Set([',', '\\', '#', '+', '<', '>', ';', '"', '='])

const escapeADString = (str: string): string => {
  let hex
  let es = str.replace(adUnsafeChars, match => {
    if (adSpecialChars[match]) {
      return '\\' + match
    } else {
      hex = match.charCodeAt(0).toString(16)
      if (hex.length % 2 !== 0) {
        hex = '0' + hex
      }
      return '\\' + hex
    }
  })
  if (es.charAt(0) === ' ') {
    es = '\\20' + (es.length > 1 ? es.substring(1) : '')
  }
  if (es.charAt(es.length - 1) === ' ') {
    es = (es.length > 1 ? es.substring(0, es.length - 1) : '') + '\\20'
  }
  return es
}

export { binarySIDToString, binaryGUIDToString, escapeADString }
