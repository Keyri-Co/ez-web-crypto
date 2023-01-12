```
                           _                                 _        
  ___ ____   __      _____| |__         ___ _ __ _   _ _ __ | |_ ___  
 / _ \_  /___\ \ /\ / / _ \ '_ \ _____ / __| '__| | | | '_ \| __/ _ \ 
|  __// /_____\ V  V /  __/ |_) |_____| (__| |  | |_| | |_) | || (_) |
 \___/___|     \_/\_/ \___|_.__/       \___|_|   \__, | .__/ \__\___/ 
                                                 |___/|_|             

...A Humble Attempt To Simplify WebCrypto
```

## Uses

The library (as an instantiated class) exposes the following methods - simplified, opinionated versions of the real thing. All Async.:

- `HMAC (secret, data)`
- `HASH (algorithm, data, length)`
- `AESMakeKey (exportable = true)`
- `AESImportKey (aes_key, exportable = true)`
- `AESEncrypt (aes_key, base_64_data, base_64_nonce = false)`
- `AESDecrypt (aes_key, base_64_nonce, base_64_cipher, returnText = false)`
- `EcMakeCryptKeys (exportable = true)`
- `EcEncrypt (privateKey, publicKey, b64data)`
- `EcDecrypt (privateKey, publicKey, b64Nonce, b64data)`
- `HKDFEncrypt (ecPrivateKey, ecPublicKey, b64data)`
- `HKDFDecrypt (ecPrivate, ecPublic, b64Salt, b64iv, b64data)`
- `EcMakeSigKeys (exportable = true)`
- `EcSignData (PrivateKey, b64data)`
- `EcVerifySig (PublicKey, b64Signature, b64data)`
- `EcdhConvertKey (unknown_key)`
- `EcdsaConvertKey (unknown_key)`


## Installation

Don't currently have an NPM repo set up (todo: set up NPM repo for this), but the library can be included as a dependency by adding it in your `package.json` file and running `npm install --save`.

```json
  "dependencies": {
    "ezcrypto": "github:Keyri-Co/EZCrypto",
  },
```
