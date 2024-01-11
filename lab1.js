// import pkcs11js from 'pkcs11js'
// import path from 'path'
// import nodeCrypto from 'crypto'
// import * as x509 from '@peculiar/x509'
// import { Crypto } from '@peculiar/webcrypto'
// import fs from 'fs'
// import * as jose from 'jose'
// import { v4 as uuid } from 'uuid'

const pkcs11js = require('pkcs11js')
const path = require('path')
const nodeCrypto = require('crypto')
const x509 = require('@peculiar/x509')
const Crypto = require('@peculiar/webcrypto').Crypto
const fs = require('fs')
const jose = require('jose')
const uuid = require('uuid').v4

const hsmConfig = {
  SLOT: process.env.HSM_SLOT || 1,
  PIN: process.env.HSM_PIN || 'mock123',
}

const connectToSlot = (_pkcs11) => {
  if (hsmConfig.SLOT === undefined || isNaN(Number(hsmConfig.SLOT))) {
    throw new Error('Something wrong with config hsm')
  }
  if (hsmConfig.PIN === undefined) {
    throw new Error('Something wrong with config hsm')
  }

  let session = null
  try {
    const slots = _pkcs11.C_GetSlotList(true)
    const slot = slots[Number(hsmConfig.SLOT)]

    // let _slot_info = _pkcs11.C_GetSlotInfo(_slot)
    // let _token_info = _pkcs11.C_GetTokenInfo(slot)
    // console.log({
    //   _slot_info,
    //   _token_info,
    // })

    session = _pkcs11.C_OpenSession(
      slot,
      pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION,
    )
    _pkcs11.C_Login(session, pkcs11js.CKU_USER, hsmConfig.PIN)
    return session
  } catch (error) {
    if (session != null) {
      _pkcs11.C_CloseSession(session)
    }
    _pkcs11.C_Finalize()
  }
}

const disconnectToSlot = (_pkcs11, _session) => {
  _pkcs11.C_Logout(_session)
  _pkcs11.C_CloseSession(_session)
  _pkcs11.C_Finalize()
}

const findObjects = (_pkcs11, _session, _template) => {
  _pkcs11.C_FindObjectsInit(_session, _template)
  const objs = []
  let hObject = _pkcs11.C_FindObjects(_session)

  if (hObject) {
    while (hObject) {
      objs.push(hObject)
      hObject = _pkcs11.C_FindObjects(_session)
    }
  }
  _pkcs11.C_FindObjectsFinal(_session)
  return objs
}

const getAttributeValue = (_pkcs11, _session, _obj, _template) => {
  const attrs = _pkcs11.C_GetAttributeValue(_session, _obj, _template)
  return attrs
}

const encrypting = (libPath, plainTextData) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    /**
     * FIND PUBLIC KEY
     */
    const objsPublic = findObjects(pkcs11, session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'ITMX Public Key' },
      { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
      // { type: pkcs11js.CKA_ID, value: "P12" },
    ])
    const publicKeyObject = objsPublic[0]

    /**
     * ENCRYPT DATA WITH PUBLIC KEY
     */
    const mechanism = { mechanism: pkcs11js.CKM_RSA_PKCS } // for encrypt
    pkcs11.C_EncryptInit(session, mechanism, publicKeyObject)
    const inData = Buffer.from(plainTextData)
    const encryptedData = Buffer.alloc(256) // Buffer.alloc(4096) // Adjust the buffer size based on your requirements
    const encryptedMessage = pkcs11.C_Encrypt(session, inData, encryptedData)
    // console.log({
    //   encryptedDataToBase64: encryptedData.toString('base64'),
    //   encryptedMessageToBase64: encryptedMessage.toString('base64'),
    // })

    disconnectToSlot(pkcs11, session)
    return encryptedMessage
  } else {
    pkcs11.C_Finalize()
  }
}

const decrypting = (libPath, inData) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    /**
     * FIND PRIVATE KEY
     */
    const objsPrivate = findObjects(pkcs11, session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'ITMX Private Key' },
      { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
      // { type: pkcs11js.CKA_ID, value: "P12" },
    ])
    const privateKeyObject = objsPrivate[0]

    /**
     * DECRYPT DATA WITH PRIVATE KEY
     */
    const decryptMechanism = { mechanism: pkcs11js.CKM_RSA_PKCS }
    pkcs11.C_DecryptInit(session, decryptMechanism, privateKeyObject)
    // const plaintextData = Buffer.from(inputData)
    const outData = Buffer.alloc(4096) // Adjust the buffer size based on your requirements
    const decryptedMessage = pkcs11.C_Decrypt(session, inData, outData)

    disconnectToSlot(pkcs11, session)
    return decryptedMessage
  } else {
    pkcs11.C_Finalize()
  }
}

const getDigest = (libPath, byte) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    /**
     * DIGEST
     */
    const outDataDigest = Buffer.alloc(256 / 8)
    pkcs11.C_DigestInit(session, { mechanism: pkcs11js.CKM_SHA256 })
    const digest = pkcs11.C_Digest(session, byte, outDataDigest)
    // pkcs11.C_DigestUpdate(session, Buffer.from('Incoming message 1'))
    // pkcs11.C_DigestUpdate(session, Buffer.from('Incoming message N'))
    // const digest = pkcs11.C_DigestFinal(session, Buffer(256 / 8))
    // console.log(digest.toString("hex"))

    disconnectToSlot(pkcs11, session)
    return digest.toString('base64')
  } else {
    pkcs11.C_Finalize()
  }
}

const signing = (libPath, plainTextData) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    /**
     * FIND PRIVATE KEY
     */
    const objsPrivate = findObjects(pkcs11, session, [
      // { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE },
      // { type: pkcs11js.CKA_LABEL, value: 'ITMX Cert' },
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'ITMX Private Key' },
      // { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
      // { type: pkcs11js.CKA_ID, value: 'P12' },
    ])
    const privateKeyObject = objsPrivate[0]
    console.log({
    //   objsPrivate,
    //   privateKeyObject,
    //   privateKeyObjectToStr: privateKeyObject.toString(),
    //   privateKeyObjectToUtf8: privateKeyObject.toString('utf8'),
    //   privateKeyObjectToBase64: privateKeyObject.toString('base64'),
      objsPrivate0: objsPrivate[0],
      objsPrivate1: objsPrivate[1],
      objsPrivate2: objsPrivate[2],
      objsPrivate3: objsPrivate[3],
    })
    console.log('after findObjects: ')

    /**
     * SIGNING DATA
     */
    const outDataSign = Buffer.alloc(256) // Buffer.alloc(2048) // Buffer.alloc(256)
    const signMechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS } // for sign
    pkcs11.C_SignInit(session, signMechanism, privateKeyObject)
    console.log('after C_SignInit')
    const signature = pkcs11.C_Sign(session, Buffer.from(plainTextData), outDataSign)
    console.log('after signature')
    // pkcs11.C_SignUpdate(session, Buffer.from(plainTextData))
    // // pkcs11.C_SignUpdate(session, Buffer.from("Incoming message N"))
    // const signature = pkcs11.C_SignFinal(session, outDataSign)

    disconnectToSlot(pkcs11, session)
    return signature
  } else {
    pkcs11.C_Finalize()
  }
}

const verifying = (libPath, plainTextData, signature) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    /**
     * FIND PUBLIC KEY
     */
    const objsPublic = findObjects(pkcs11, session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'ITMX Public Key' },
      { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
      { type: pkcs11js.CKA_ID, value: 'P12' },
    ])
    const publicKeyObject = objsPublic[0]

    /**
     * VERIFYING DATA
     */
    const verifyMechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }
    pkcs11.C_VerifyInit(session, verifyMechanism, publicKeyObject)
    pkcs11.C_VerifyUpdate(session, Buffer.from(plainTextData))
    // pkcs11.C_VerifyUpdate(session, Buffer.from("Incoming message N"))
    const verify = pkcs11.C_VerifyFinal(session, signature)
    // console.log({ verify })

    disconnectToSlot(pkcs11, session)
    return verify
  } else {
    pkcs11.C_Finalize()
  }
}

const wrapAndUnwrap = (libPath) => {
  const pkcs11 = new pkcs11js.PKCS11()
  pkcs11.load(libPath)
  pkcs11.C_Initialize()
  const session = connectToSlot(pkcs11)
  if (session) {
    // const wrappingAndUnwarppingKeyTemplate = [
    //   { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
    //   { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
    //   { type: pkcs11js.CKA_TOKEN, value: true },
    //   { type: pkcs11js.CKA_PRIVATE, value: true },
    //   { type: pkcs11js.CKA_LABEL, value: 'Secret key to wrapping and unwrapping' },
    //   { type: pkcs11js.CKA_ENCRYPT, value: true },
    //   { type: pkcs11js.CKA_DECRYPT, value: true },
    //   { type: pkcs11js.CKA_WRAP, value: 2048 },
    //   { type: pkcs11js.CKA_UNWRAP, value: true },
    //   { type: pkcs11js.CKA_VALUE_LEN, value: 256 / 8 },
    // ]
    // const secretKey = pkcs11.C_GenerateKey(session, { mechanism: pkcs11js.CKM_AES_KEY_GEN }, wrappingAndUnwarppingKeyTemplate)
    // // pkcs11.C_GenerateKey(session, { mechanism: pkcs11js.CKM_AES_KEY_GEN }, wrappingAndUnwarppingKeyTemplate)
    const wrappingKey = findObjects(pkcs11, session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'Secret key to wrapping and unwrapping' },
    ])
    const wrappingKeyObject = wrappingKey[0]
    console.log({
      wrappingKeyObject,
      wrappingKeyObjectType: typeof wrappingKeyObject,
    })
    const wrappingKeyAttributes = getAttributeValue(
      pkcs11,
      session,
      wrappingKeyObject,
      [
        { type: pkcs11js.CKA_EXTRACTABLE },
        { type: pkcs11js.CKA_WRAP },
        { type: pkcs11js.CKA_UNWRAP },
      ]
    )
    if (wrappingKeyAttributes) {
      console.log('### wrapping key attributes ###')
      for (const attribute of wrappingKeyAttributes) {
          console.log({
            type: attribute.type,
            value: attribute.value,
            valueStr: attribute.value.toString(),
            valueToUtf8: attribute.value.toString("utf-8"),
            valueToHex: attribute.value.toString("hex"),
            valueToBase64: attribute.value.toString("base64"),
          })
      }
    }

    const keyToWrap = findObjects(
      pkcs11,
      session,
      [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
        { type: pkcs11js.CKA_EXTRACTABLE, value: true },
        { type: pkcs11js.CKA_SENSITIVE, value: true },
        { type: pkcs11js.CKA_LABEL, value: 'ITMX Private Key' },
        
        // { type: pkcs11js.CKA_LABEL, value: 'The key to wrap' },
      ]
    )
    const keyToWrapObject = keyToWrap[0]
    console.log({
      keyToWrapObject,
    })

    const wrapMechanism = { mechanism: pkcs11js.CKM_AES_KEY_WRAP_PAD }
    const wrappedKey = pkcs11.C_WrapKey(
      session,
      wrapMechanism,
      wrappingKeyObject,
      keyToWrapObject,
      Buffer.alloc(2048)
    )
    const unwrappedKey = pkcs11.C_UnwrapKey(
      session,
      wrapMechanism,
      wrappingKeyObject,
      wrappedKey,
      [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
        { type: pkcs11js.CKA_EXTRACTABLE, value: true },
        { type: pkcs11js.CKA_SENSITIVE, value: false },
        { type: pkcs11js.CKA_LABEL, value: 'ITMX Private Key 2' },
        
        // { type: pkcs11js.CKA_EXTRACTABLE, value: true },
        // { type: pkcs11js.CKA_SENSITIVE, value: false },
        // { type: pkcs11js.CKA_LABEL, value: 'The key to wrap 2' },
      ]
    )
    const unwrappedKeyObject = unwrappedKey
    const attributesUnwrap = getAttributeValue(
      pkcs11,
      session,
      unwrappedKeyObject,
      [
        { type: pkcs11js.CKA_LABEL },
        { type: pkcs11js.CKA_EXTRACTABLE },
        { type: pkcs11js.CKA_SENSITIVE },
        { type: pkcs11js.CKA_VALUE },
      ]
    )
    if (attributesUnwrap) {
      console.log('### unwraped key attributes ###')
      for (const attribute of attributesUnwrap) {
        if (attribute.type === pkcs11js.CKA_LABEL) {
          console.log({
            type: attribute.type,
            value: attribute.value,
            valueStr: attribute.value.toString(),
          })
        // } else if (attribute.type === pkcs11js.CKA_CLASS) {
        } else if (attribute.type === pkcs11js.CKA_VALUE) {
          console.log({
            type: attribute.type,
            value: attribute.value,
            // valueToHex: attribute.value.toString("hex"),
            valueToBase64: attribute.value.toString("base64"),
          })
        } else {
          console.log({
            type: attribute.type,
            value: attribute.value,
            valueStr: attribute.value.toString(),
            valueToUtf8: attribute.value.toString("utf-8"),
            valueToHex: attribute.value.toString("hex"),
            valueToBase64: attribute.value.toString("base64"),
          })
        }
      }
    }

    // Print the wrapped and unwrapped keys
    console.log({
      wrappedKey,
      // wrappedKeyToStr: wrappedKey.toString(),
      // wrappedKeyToUtf8: wrappedKey.toString('utf8'),
      // wrappedKeyToHex: wrappedKey.toString('hex'),
      // wrappedKeyToBase64: wrappedKey.toString('base64'),
      unwrappedKey,
      // unwrappedKeyToStr: unwrappedKey.toString(),
      // unwrappedKeyToUtf8: unwrappedKey.toString('utf8'),
      // unwrappedKeyToHex: unwrappedKey.toString('hex'),
      // unwrappedKeyToBase64: unwrappedKey.toString('base64'),
    })

    disconnectToSlot(pkcs11, session)
  } else {
    pkcs11.C_Finalize()
  }
}

const testOldSign = (plainTextData) => {
  try {
    const bankCode = '004'

    // const crypto = new Crypto()
    // x509.cryptoProvider.set(crypto)
    // const publicKey = 'certificates/' + bankCode + '/public.cer'
    // if (!fs.existsSync(publicKey)) {
    //   console.error('### publicKey is not found ###')
    // }
    // // const cert = new x509.X509Certificate(
    // //   fs.readFileSync(publicKey, { encoding: 'utf-8' }),
    // // )

    // // getDigest
    // const hash = nodeCrypto.createHash('sha256').update(Buffer.from(plainTextData)).digest('base64')
    // console.log({
    //   hash,
    // })

    const oldSignature = nodeCrypto.sign(
      'RSA-SHA256',
      Buffer.from(plainTextData),
      fs.readFileSync(path.join('certificates', bankCode, 'private.pem'), {
        encoding: 'utf8',
      }),
    )

    // const isVerify = nodeCrypto.verify(
    //   'RSA-SHA256',
    //   Buffer.from(plainTextData),
    //   fs.readFileSync(path.join('certificates', bankCode, 'public.cer')),
    //   oldSignature,
    // )

    console.log({
      // publicKeyRaw: fs.readFileSync(publicKey, { encoding: "utf-8" }),
      // publicKey: JSON.stringify(cert.publicKey),

      // cert: JSON.stringify(cert),
      // issuer: cert.issuer,
      // serialNumber: parseInt(cert.serialNumber, 16),
      // subject: cert.subject,
      oldSignature,
      // oldSignatureToStr: oldSignature.toString(),
      // oldSignatureToHex: oldSignature.toString('hex'),
      oldSignatureToBase64: oldSignature.toString('base64'),
      // isVerify,
    })
  } catch (error) {
    console.error('### error ###')
    console.error(error)
  }
}

try {
  const plainTextData = 'Your message'
  // const plainTextData = '256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|256|'

  testOldSign(plainTextData)
  // wrapAndUnwrap('/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so')

  // const encryptedMessage = encrypting(
  //   "/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so",
  //   plainTextData
  // )
  // if (encryptedMessage) {
  //   const decryptedMessage = decrypting(
  //     "/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so",
  //     encryptedMessage
  //   )

  //   console.log({
  //     encrypt: {
  //       encryptedMessage,
  //       // encryptedMessageToStr: encryptedMessage.toString(),
  //       // encryptedMessageToHex: encryptedMessage.toString("hex"),
  //       // encryptedMessageToBase64: encryptedMessage.toString("base64"),
  //     },
  //     decrypt: {
  //       decryptedMessage,
  //       decryptedMessageToStr: decryptedMessage.toString(),
  //       // decryptedMessageToHex: decryptedMessage.toString("hex"),
  //       // decryptedMessageToBase64: decryptedMessage.toString("base64"),
  //     },
  //   })
  // }

  const signature = signing(
    '/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
    plainTextData,
  )
  if (signature) {
    // const isVerify = verifying(
    //   '/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
    //   plainTextData,
    //   signature,
    // )

    console.log({
      signature: {
        signature,
        // signatureToStr: signature.toString(),
        // signatureToHex: signature.toString('hex'),
        signatureToBase64: signature.toString('base64'),
      },
      // isVerify,
    })
  }
} catch (error) {
  console.error('### catch ###')
  console.error(error)
}

// export default {
//   encrypting,
//   decrypting,
//   getDigest,
//   signing,
//   verifying,
//   wrapAndUnwrap,
//   // testOldSign,
// }
