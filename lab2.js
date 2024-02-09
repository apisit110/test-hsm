import pkcs11js from 'pkcs11js'
import path from 'path'
import fs from 'fs'
import util from 'util'
// import nodeCrypto from 'crypto'
// import * as x509 from '@peculiar/x509'
// import { Crypto } from '@peculiar/webcrypto'
// import * as jose from 'jose'
import { v4 as uuid } from 'uuid'

// const pkcs11js = require('pkcs11js')
// const path = require('path')
// const fs = require('fs')
// const util = require('util')
// const nodeCrypto = require('crypto')
// const x509 = require('@peculiar/x509')
// const Crypto = require('@peculiar/webcrypto').Crypto
// const jose = require('jose')
// const uuid = require('uuid').v4

const exec = util.promisify(require('child_process').exec)

const hsmConfig = {
  DEVICE: process.env.HSM_DEVICE,
  SLOT: process.env.HSM_SLOT,
  PIN: process.env.HSM_PIN,
  SPEC: process.env.HSM_SPEC,
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

// const getAttributeValue = (_pkcs11, _session, _obj, _template) => {
//   const attrs = _pkcs11.C_GetAttributeValue(_session, _obj, _template)
//   return attrs
// }

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
      { type: pkcs11js.CKA_ID, value: 'P12' },
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
      { type: pkcs11js.CKA_ID, value: 'P12' },
    ])
    const privateKeyObject = objsPrivate[0]

    /**
     * DECRYPT DATA WITH PRIVATE KEY
     */
    const decryptMechanism = { mechanism: pkcs11js.CKM_RSA_PKCS }
    pkcs11.C_DecryptInit(session, decryptMechanism, privateKeyObject)
    const outData = Buffer.alloc(256) // Buffer.alloc(4096) // Adjust the buffer size based on your requirements
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
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_LABEL, value: 'ITMX Private Key' },
      { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA },
      { type: pkcs11js.CKA_ID, value: 'P12' },
    ])
    const privateKeyObject = objsPrivate[0]

    /**
     * SIGNING DATA
     */
    const outDataSign = Buffer.alloc(256) // Buffer.alloc(2048) // Buffer.alloc(256)
    const signMechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS } // for sign
    pkcs11.C_SignInit(session, signMechanism, privateKeyObject)
    const signature = pkcs11.C_Sign(session, Buffer.from(plainTextData), outDataSign)

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

    disconnectToSlot(pkcs11, session)
    return verify
  } else {
    pkcs11.C_Finalize()
  }
}

/**
 * function for sign message by command interface
 * @param plainTextData the message to sign
 * @returns {Buffer} signature or undefiend for error
 */
const signingByCommand = async (plainTextData) => {
  /**
   * Validate
   */
  if (!hsmConfig.DEVICE || !hsmConfig.SLOT || !hsmConfig.PIN || !hsmConfig.SPEC) return undefined

  const homePath = process.cwd()
  const _random = uuid()
  const config = {
    device: hsmConfig.DEVICE,
    user: `USR_000${hsmConfig.SLOT?.toString()}`,
    password: hsmConfig.PIN,
    spec: hsmConfig.SPEC, // cxitool ListKeys

    pathToAdministration: path.join(homePath, 'Utimaco', 'Administration'),
    pathToHsmFolder: path.join(homePath, 'hsm'),
    pathToMessageFile: path.join(homePath, 'hsm', `${_random}-message.txt`),
    pathToSignatureBinaryFile: path.join(homePath, 'hsm', `${_random}-signature.sig`),
  }

  const commandToSign = `${config.pathToAdministration}/cxitool Dev=${config.device} LogonPass=${config.user},${config.password} spec=${config.spec} InFile="${config.pathToMessageFile}" Signature="${config.pathToSignatureBinaryFile}",raw Sign=SHA256,on_hsm,PKCS1`
  try {
    /**
     * Clean file data like
     * @file {String} message.txt is contain message to sign
     * @file {Binary} signature.sig is contain signature
     */
    if (!fs.existsSync(config.pathToHsmFolder)) fs.mkdirSync(config.pathToHsmFolder, { recursive: true })
    if (fs.existsSync(config.pathToMessageFile)) fs.rmSync(config.pathToMessageFile, { force: true })
    if (fs.existsSync(config.pathToSignatureBinaryFile)) fs.rmSync(config.pathToSignatureBinaryFile, { force: true })

    fs.writeFileSync(config.pathToMessageFile, plainTextData, { encoding: 'utf8' })
    await exec(commandToSign)
    const signature = fs.readFileSync(config.pathToSignatureBinaryFile)

    fs.rmSync(config.pathToMessageFile, { force: true })
    fs.rmSync(config.pathToMessageFile, { force: true })
    return signature
  } catch (error) {
    console.log('### signingByCommand ###')
    console.log(error)
  }
}

// const testNoHsmSign = (plainTextData) => {
//   try {
//     const bankCode = '004'

//     // const crypto = new Crypto()
//     // x509.cryptoProvider.set(crypto)
//     // const publicKey = 'certificates/' + bankCode + '/public.cer'
//     // if (!fs.existsSync(publicKey)) {
//     //   console.error('### publicKey is not found ###')
//     // }
//     // // const cert = new x509.X509Certificate(
//     // //   fs.readFileSync(publicKey, { encoding: 'utf-8' }),
//     // // )

//     // // getDigest
//     // const hash = nodeCrypto.createHash('sha256').update(Buffer.from(plainTextData)).digest('base64')
//     // console.log({
//     //   hash,
//     // })

//     const oldSignature = nodeCrypto.sign(
//       'RSA-SHA256',
//       Buffer.from(plainTextData),
//       fs.readFileSync(path.join('certificates', bankCode, 'private.pem'), {
//         encoding: 'utf8',
//       }),
//     )

//     // const isVerify = nodeCrypto.verify(
//     //   'RSA-SHA256',
//     //   Buffer.from(plainTextData),
//     //   fs.readFileSync(path.join('certificates', bankCode, 'public.cer')),
//     //   oldSignature,
//     // )

//     console.log({
//       // publicKeyRaw: fs.readFileSync(publicKey, { encoding: "utf-8" }),
//       // publicKey: JSON.stringify(cert.publicKey),

//       // cert: JSON.stringify(cert),
//       // issuer: cert.issuer,
//       // serialNumber: parseInt(cert.serialNumber, 16),
//       // subject: cert.subject,
//       oldSignature,
//       // oldSignatureToStr: oldSignature.toString(),
//       // oldSignatureToHex: oldSignature.toString('hex'),
//       oldSignatureToBase64: oldSignature.toString('base64'),
//       // isVerify,
//     })
//   } catch (error) {
//     console.error('### error ###')
//     console.error(error)
//   }
// }

// const main = async () => {
//   try {
//     const plainTextData = 'Your message'

//     // testNoHsmSign(plainTextData)

//     /**
//      * Encryting and decryption
//      */
//     // const encryptedMessage = encrypting(
//     //   "/home/node/app/Utimaco/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so",
//     //   plainTextData
//     // )
//     // if (encryptedMessage) {
//     //   const decryptedMessage = decrypting(
//     //     "/home/node/app/Utimaco/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so",
//     //     encryptedMessage
//     //   )

//     //   console.log({
//     //     encrypt: {
//     //       encryptedMessage,
//     //       // encryptedMessageToStr: encryptedMessage.toString(),
//     //       // encryptedMessageToHex: encryptedMessage.toString("hex"),
//     //       // encryptedMessageToBase64: encryptedMessage.toString("base64"),
//     //     },
//     //     decrypt: {
//     //       decryptedMessage,
//     //       decryptedMessageToStr: decryptedMessage.toString(),
//     //       // decryptedMessageToHex: decryptedMessage.toString("hex"),
//     //       // decryptedMessageToBase64: decryptedMessage.toString("base64"),
//     //     },
//     //   })
//     // }

//     /**
//      * Signing and verifying
//      */
//     // const signature = signing(
//     //   '/home/node/app/Utimaco/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
//     //   plainTextData,
//     // )
//     // const digest = getDigest(
//     //   '/home/node/app/Utimaco/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
//     //   Buffer.from(plainTextData)
//     // )
//     // console.log({ digest })
//     // if (signature) {
//     //   // const isVerify = verifying(
//     //   //   '/home/node/app/Utimaco/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
//     //   //   plainTextData,
//     //   //   signature,
//     //   // )

//     //   console.log({
//     //     digest,
//     //     signature: {
//     //       signature,
//     //       // signatureToStr: signature.toString(),
//     //       // signatureToHex: signature.toString('hex'),
//     //       signatureToBase64: signature.toString('base64'),
//     //     },
//     //     // isVerify,
//     //   })
//     // }

//     /**
//      * Signing by command
//      */
//     const signature = await signingByCommand(
//       plainTextData,
//     )
//     console.log({
//       signature,
//       signatureToBase64: signature.toString('base64'),
//     })
//   } catch (error) {
//     console.error('### catch ###')
//     console.error(error)
//   }
// }
// main()

export default {
  encrypting,
  decrypting,
  getDigest,
  signing,
  verifying,
  signingByCommand,
}
