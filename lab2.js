const pkcs11js = require('pkcs11js')
const path = require('path')
const nodeCrypto = require('crypto')
const fs = require('fs')

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
    // console.log({ verify })

    disconnectToSlot(pkcs11, session)
    return verify
  } else {
    pkcs11.C_Finalize()
  }
}

const testOldSign = (plainTextData) => {
  try {
    const bankCode = '004'

    // getDigest
    const oldDigest = nodeCrypto.createHash('sha256').update(Buffer.from(plainTextData)).digest('base64')
    console.log({ oldDigest })

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
      oldSignature,
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

  testOldSign(plainTextData)

  const digest = getDigest(
    '/home/node/app/x86-64-2/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so',
    Buffer.from(plainTextData),
  )
  console.log({ digest })
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
