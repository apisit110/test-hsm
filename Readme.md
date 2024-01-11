## step to imprement hsm

I have some key to sign and encrypt

- private.pem
- public.cer

## Convert to PKCS#12 (.p12)

```bash
openssl pkcs12 -export -out keyStore.p12 -inkey private.pem -in public.cer
```

## Import PKCS#12 (P12) File to HSM

```bash
/home/node/app/x86-64-2/Administration/p11tool2 Slot=1 LoginUser=mock123 \
CertAttr=CKA_LABEL="ITMX Cert",CKA_ID=P12 \
PubKeyAttr=CKA_LABEL="ITMX Public Key",CKA_ID=P12 \
PrvKeyAttr=CKA_LABEL="ITMX Private Key",CKA_ID=P12,CKA_SIGN=CK_TRUE \
ImportP12=/home/node/app/certificates/004/keyStore.p12,ask

# or

/home/node/app/x86-64-2/Administration/p11tool2 Slot=1 LoginUser=mock123 \
CertAttr=CKA_LABEL="ITMX Cert",CKA_ID=P12 \
PrvKeyAttr=CKA_LABEL="ITMX Private Key",CKA_ID=P12,CKA_SIGN=CK_TRUE \
ImportP12=/home/node/app/certificates/004/keyStore.p12,ask
```

when excute ListObject i got 3 object following command

```bash
/home/node/app/x86-64-2/Administration/p11tool2 Slot=1 LoginUser=mock123 ListObjects
```

- 1 CKO_CERTIFICATE
- 1 CKO_PUBLIC_KEY
- 1 CKO_PRIVATE_KEY

## Next step to the code lab2.js

i have testOldSign function and signing function

the testOldSign function is currently running is NOT HSM, read the key in machine and signing excryptting

the signing function is new coding to implement USE HSM, signing excryptting by HSM it secure


## Problem

i don't know why signature is not same value when i try testOldSign function and signing function

i try to use openssl sign data by private key to compare the signature between openssl and testOldSign function, got the save value.

```bash
echo -en "Your message" > message.txt
openssl dgst -sha256 -sign private.pem -out signature.bin message.txt
base64 -i signature.bin -o signature_base64.txt
cat signature_base64.txt
```

expected to same signature

## run lab2.js

installed or have software for hsm

install nodejs, version testing is v18.16.0

create cs_pkcs11_r3.cfg file linux at /usr/local/etc/utimaco/cs_pkcs11_R3.cfg

```bash
npm init -y
npm install
node lab2.js
```
