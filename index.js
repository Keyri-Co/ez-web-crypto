// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
//
// Class with methods to make working with subtle crypto
// easier and more obvious
//

export default class EZCrypto {
  
  #crypto;
  
  constructor() {
    if(typeof window == "undefined" && typeof self == "undefined"){
      this.#nodeEnvLoad();
    } else {
      try{
        this.#crypto = window?.crypto;
        this.#crypto.CryptoKey = window?.CryptoKey;
      } catch(e){
        this.#crypto = self?.crypto;
        this.#crypto.CryptoKey = self?.CryptoKey;
      }
    } 
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  #nodeEnvLoad = async () => {
    this.#crypto =  await Object.getPrototypeOf(async function(){}).constructor(
`
      return await import( "crypto" ).then((m) => {return m.default.webcrypto});
`
    )();  
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  #sleep = async (duration) => {
    await new Promise((s,j) => {setTimeout(() => {return s(true)},duration)});
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     base64ToArray
  // What is this: Take a base64 string. Convert it to a Uint8Array...
  //
  // Arguments:    strng: - base64 encoded string
  //
  // Returns:      Uint8Array
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  base64ToArray(strng) {
    return Uint8Array.from(atob(strng), (c) => c.charCodeAt(0));
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     arrayToBase64
  // What is this: take a Uint8Array, make it a valid base64 string
  //
  // Arguments:    ary: - Uint8Array
  //
  // Returns:      Base64 String
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  arrayToBase64(utf8Bytes) {
    // Split the bytes into smaller chunks to avoid call stack issues
    const chunkSize = 8192;
    const chunks = [];

    for (let i = 0; i < utf8Bytes.length; i += chunkSize) {
      const chunk = utf8Bytes.subarray(i, i + chunkSize);
      chunks.push(String.fromCharCode.apply(null, chunk));
    }

    // Convert the bytes to a base64 string
    const base64 = btoa(chunks.join(''));

    return base64;
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     hmac (static) (async)
  // What is this: Create a cryptographic signature for a piece of data given a *SHARED* secret.
  //               Similar to ECDSA - Except both parties have to have the secret-key in advance
  //               to make it work.
  //
  // Arguments:    secret - this is the shared secret
  //               data   - this is the string you're encrypting
  //
  // Returns:      hex encoded 32 character string or something...(todo: check length - better def)
  // Notes:        https://stackoverflow.com/questions/47329132/how-to-get-hmac-with-crypto-web-api#47332317
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  HMAC = async (secret, data) => {
    await this.#sleep(0);

    // To do work, we need to convert text to Uint8Arrays
    let encoder = new TextEncoder("utf-8");
    let encodedSecret = encoder.encode(secret);
    let encodedData = encoder.encode(data);

    // Create our HMAC Key
    let key = await this.#crypto.subtle.importKey(
      "raw",
      encodedSecret,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign", "verify"]
    );

    // HMAC Sign our data with our HMAC Key
    let sig = await this.#crypto.subtle.sign("HMAC", key, encodedData);

    // Turn the signature into an array; then into hex-text
    // (todo: Maybe this is its own method...?)
    //
    let b = new Uint8Array(sig);
    let str = Array.prototype.map
      .call(b, (x) => ("00" + x.toString(16)).slice(-2))
      .join("");

    return str;
  }


  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     HASH (static) (async)
  // What is this: The digest() method of the SubtleCrypto interface generates a digest of the given data. 
  //               A digest is a short fixed-length value derived from some variable-length input.
  //               Cryptographic digests should exhibit collision-resistance, meaning that it's hard to come up 
  //               with two different inputs that have the same digest value.
  //
  // Arguments:    algo - this is the string you're hashing for
  //               data   - This is the algorithm you're using to hash the data with (SHA-1, SHA-256, SHA-384, SHA-512)
  //
  // Returns:      the hash of the data you provided as a base64 string
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  HASH = async (algo, data, len) => {

    await this.#sleep(0);

    let hash = await this.#crypto.subtle.digest(algo, new TextEncoder().encode(data));
    
    let ary = new Uint8Array(hash);

    let outAry;

    if(len){
      // initialize outAry to the desired size
      outAry = new Uint8Array(len,0);

      let min = Math.min(len, ary.length);
      let max = Math.max(len, ary.length);

      for(var i = 0; i < max; i++){
        outAry[i%len] = outAry[i%len] ^ ary[i%ary.length];
      }
    } else {
      outAry = ary;
    }

    return this.arrayToBase64(new Uint8Array(outAry));

  }



  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  //
  // Function:     PASSWORD_ENCRYPT
  // What is this: Dead simple method to encrypt a piece of data with a password
  //               that can later be decrypted needing only that password 
  //
  // Arguments:    password: string; plaintext string of user's password
  //               base64data: string; what you want to encrypt
  //
  // Returns:      base64 encoded, stringified object containing the AES key used
  //               to encrypt the data, and the ciphertext itself
  // Notes:
  //
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  PASSWORD_ENCRYPT = async(password, base64data) => {

      await this.#sleep(0);

      for(let i = 0; i < 10; i++){
        password = await this.HASH("SHA-512", password);
      }
      
      let passwordHash = btoa(password);
    
      let aes = await this.AESMakeKey(true);

      let output = await this.AESEncrypt(aes, base64data, passwordHash);

      return btoa(JSON.stringify({ciphertext: output.ciphertext, aes}));
  }



  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  //
  // Function:     PASSWORD_DECRYPT
  // What is this: Counterparty to PASSWORD_ENCRYPT. Give it a password, and
  //               the encrypted data from PASSWORD_ENCRYPT; it should give you
  //               the initial plaintext...
  //
  // Arguments:    password: string; plaintext string of user's password
  //               base64data: password-data
  //
  // Returns:      plaintext
  //
  // Notes:
  //
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  PASSWORD_DECRYPT = async(password, base64data) => {

    await this.#sleep(0);

    for(let i = 0; i < 10; i++){
      password = await this.HASH("SHA-512", password);
    }
      
    let passwordHash = btoa(password);

    let encryptedDataObject = JSON.parse(atob(base64data));
  
    let aes = await this.AESImportKey(encryptedDataObject.aes,false);

    let ciphertext = encryptedDataObject.ciphertext;

    let plaintext = await this.AESDecrypt(aes, passwordHash, ciphertext, true);

    return plaintext;
}








  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESMakeKey (async)
  // What is this: Generate an AES Key and return its hex
  //
  // Arguments:    *NONE*
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  AESMakeKey = async (exportable = true) => {
    await this.#sleep(0);

    // 1.) Generate the Key
    let key = await this.#crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      exportable,
      ["encrypt", "decrypt"]
    );


    // 2.) 
    if(exportable){
      //Return it as b64 if its exportable
      
      let out = await this.#crypto.subtle.exportKey("raw", key);
      return this.arrayToBase64(new Uint8Array(out));
    } else {
      // else return the CryptoKey Object
      
      return key;
    }
  };
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESImportKey (async)
  // What is this: Generate an AES Key and return its hex
  //
  // Arguments:    base64 string
  //
  // Returns:      Live AES Key
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  AESImportKey = async (aes_key, exportable = true) => {
    await this.#sleep(0);


    if(aes_key instanceof this.#crypto.CryptoKey){
      return aes_key;
    } else {

      // 1.) Generate the Key
      return await this.#crypto.subtle.importKey(
          "raw",
          this.base64ToArray(aes_key).buffer,
          "AES-GCM",
          exportable,
          ["encrypt", "decrypt"]
        );
    }
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESEncrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               data: uInt8Array
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESEncrypt(base_64_key, base_64_data, base_64_nonce = false) {
    await this.#sleep(0);
    
    // 0.) Pass Key to 
    let aes_key = await this.AESImportKey(base_64_key);


    // 3.) Create a nonce why not?
    let nonce;
    
    if(base_64_nonce){
      nonce = this.base64ToArray(base_64_nonce);
    } else {
      nonce = this.#crypto.getRandomValues(new Uint8Array(16));
    }

    // 4.) encrypt our data
    let encrypted = await this.#crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      this.base64ToArray(base_64_data)
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      iv: this.arrayToBase64(nonce),
    };
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESDecrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               nonce: base64 of the nonce used at encryption (ok if it is public)
  //               ciphertext: base64 of what's been encoded
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESDecrypt(base_64_key, base_64_nonce, base_64_cipher, returnText = false) {
    await this.#sleep(0);

    // 1.) Convert out from base64 to array
    let aes_key = await this.AESImportKey(base_64_key);
    let nonce_ary = this.base64ToArray(base_64_nonce);
    let cipher_ary = this.base64ToArray(base_64_cipher);
    let decrypted;



    // 3.) Decrypt
    decrypted = await this.#crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce_ary },
      aes_key,
      cipher_ary
    );

    if(!returnText){
      return decrypted;
    } else {
      decrypted = new Uint8Array(decrypted);

      decrypted = new TextDecoder().decode(decrypted);

      return decrypted;
    }
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcMakeCryptKeys (async)
  // What is this: Given
  //
  // Arguments:    none
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcMakeCryptKeys = async (exportable = true) => {
    await this.#sleep(0);

    // Step 1) Create ECDH KeyS
    let keys = await this.#crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      exportable,
      ["deriveKey","deriveBits"]
    );

    // Step 2) Export keys to SPKI|PKCS8|JWK|RAW format
    let exportKeys;

    if(exportable){
      exportKeys = await Promise.all([
          this.#crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
          this.#crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
          this.#crypto.subtle.exportKey("jwk", keys.publicKey).then((key) => {
            return (key);
          }),
          this.#crypto.subtle.exportKey("jwk", keys.privateKey).then((key) => {
            return (key);
          }),
          this.#crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key));
          }),
          this.#crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key).slice(1,1000));
          })
      ]);
      
    } else {
      exportKeys = await Promise.all([
        //
          this.#crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
        //
        (new Promise((s,j) => {return s(keys.privateKey)})),
        //
          this.#crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key));
          }),
        //
          this.#crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key).slice(1,1000));
          })
      ]);
    }

    if(exportable){
      return { 
        publicKey: exportKeys[0], 
        privateKey: exportKeys[1], 
        jwkPublicKey: exportKeys[2], 
        jwkPrivateKey: exportKeys[3], 
        rawPublicKey: exportKeys[4],
        rawPublicKeyLite: exportKeys[5]
      };
    } else {
        return { 
          publicKey: exportKeys[0], 
          privateKey: exportKeys[1], 
          rawPublicKey: exportKeys[2], 
          rawPublicKeyLite: exportKeys[3]
        };
    }

    // Step 3) Convert the keys to base64 and return...
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcEncrypt (async)
  // What is this: Encrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcEncrypt = async (b64Private, b64Public, b64data) => {
    await this.#sleep(0);

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    
    // 2.) generate shared key
    let aes_key = await this.#crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    )
    
    // 3.) Work smarter, not harder, dummy...
    return await this.AESEncrypt(aes_key, b64data);
  
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcDecrypt (async)
  // What is this: Decrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64nonce: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcDecrypt = async (b64Private, b64Public, b64Nonce, b64data, returnText = false) => {

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    let nonce = this.base64ToArray(b64Nonce);
    let data = this.base64ToArray(b64data);
    let decrypted;

    // 2.) generate shared key
    let aes_key = await this.#crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // 3..) decrypt our data
    const decryptedData = await this.#crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data
    );

    if(!returnText){
      return decryptedData;
    } else {
      decrypted = new Uint8Array(decryptedData);
      decrypted = new TextDecoder().decode(decrypted);
      return decrypted;
    }
  };
  



















  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     HKDFEncrypt (async)
  // What is this: Encrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  HKDFEncrypt = async (b64Private, b64Public, b64data) => {
    await this.#sleep(0);

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    
    // 2.) generate shared secret for HKDF
    //
    let sharedSecret = await this.#crypto.subtle.deriveBits({ 
      "name": "ECDH", 
      "namedCurve": "P-256", 
      "public": publicKey 
    },privateKey,256);
    
    // 3.) convert shared-secret into a key
    //
    let sharedSecretKey = await this.#crypto.subtle.importKey(
      "raw", sharedSecret, 
      { "name": 'HKDF' }, 
      false, 
      ['deriveKey','deriveBits']
    );
    
    // 4.) create SALT
    //
    let salt = this.#crypto.getRandomValues(new Uint8Array(16));
    
    // 5.) convert the live-shared-secret-key into an aes key
    //
    let derivedKey = await this.#crypto.subtle.deriveBits({
      "name": 'HKDF', 
      "hash": 'SHA-256', 
      "salt": salt,
      "info": new Uint8Array([])},
      sharedSecretKey,256
    );
    
    //
    // 6.) 
    // THIS SHOULD NOT BE THIS HARD!
    //
    //     Convert the Key-Array to a live Key
    let aes_key = await this.#crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      false,
      ["encrypt","decrypt"]
    );
    
    // 7.) Init Vector
    //
    //
    let iv = this.#crypto.getRandomValues(new Uint8Array(16));
    
    // 7.) Encrypt
    //
    //
    let encrypted = await this.#crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aes_key,
      this.base64ToArray(b64data)
    );
    
    // 8.) Base64 and return our data...
    return {
      "ciphertext": this.arrayToBase64(new Uint8Array(encrypted)),
      "salt": this.arrayToBase64(salt),
      "iv": this.arrayToBase64(iv)
    };

  
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     HKDFDecrypt (async)
  // What is this: Decrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64nonce: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  HKDFDecrypt = async (b64Private, b64Public, b64Salt, b64iv, b64data, returnText = false) => {
    await this.#sleep(0);

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    
    let privateKey = await this.EcdhConvertKey(b64Private);
    
    let salt = this.base64ToArray(b64Salt);
    let iv = this.base64ToArray(b64iv);
    let data = this.base64ToArray(b64data);

    let decrypted;
    
    
    // 2.) generate shared secret for HKDF
    //
    let sharedSecret = await this.#crypto.subtle.deriveBits({ 
      "name": "ECDH", 
      "namedCurve": "P-256", 
      "public": publicKey 
    },privateKey,256);
    
    // 3.) convert shared-secret into a key
    //
    let sharedSecretKey = await this.#crypto.subtle.importKey(
      "raw", sharedSecret, 
      { "name": 'HKDF' }, 
      false, 
      ['deriveKey','deriveBits']
    );
    
    // 4.) convert the live-shared-secret-key into an aes key
    //
    let derivedKey = await this.#crypto.subtle.deriveBits({
      "name": 'HKDF', 
      "hash": 'SHA-256', 
      "salt": salt,
      "info": new Uint8Array([])},
      sharedSecretKey,256
    );

    //
    // 5.) 
    //     Convert the Key-Array to a live Key
    let aes_key = await this.#crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      false,
      ["encrypt","decrypt"]
    );

    // 6.) decrypt our data
    //
    let aes_data;
    try{
        aes_data = await this.#crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        aes_key,
        data
      );
    } catch(e){
      console.log({name: e.name, stack: e.stack, message: e.message});
    }

    if(!returnText){
      return aes_data;
    } else {
      decrypted = new Uint8Array(aes_data);
      decrypted = new TextDecoder().decode(decrypted);
      return decrypted;
    }

  };
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcMakeSigKeys (async)
  // What is this: Given
  //
  // Arguments:    none
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  EcMakeSigKeys = async (exportable = true) => {
    await this.#sleep(0);

  // Step 1) Create ECDSA KeyS
    let keys = await this.#crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      exportable,
      ["sign","verify"]
    );
    
    let b64Keys;

  // Step 2a) IF EXTRACTABLE: Export keys to SPKI|PKCS8 format
    if(exportable){
      b64Keys = await Promise.all([
        this.#crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
          return this.arrayToBase64(new Uint8Array(key));
        }),
        this.#crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
          return this.arrayToBase64(new Uint8Array(key));
        })
      ]);
      
      return { publicKey: b64Keys[0], privateKey: b64Keys[1] };

    } else {
      
  // Step 2b) NOT NOT NOT EXTRACTABLE: Export just the public key
      b64Keys = await Promise.all([
        this.#crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
          return this.arrayToBase64(new Uint8Array(key));
        })
      ]);
      return { publicKey: b64Keys[0], privateKey: keys.privateKey };
    }

  };
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcSignData (async)
  // What is this: Create a crypto-signature from a private key and data
  //
  // Arguments:    base64privateKey: string;
  //               data: Uint8Array;
  //
  // Returns:      base64 encoded signature
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcSignData = async (b64PrivateKey, b64data) => {
    await this.#sleep(0);

    // 1.) convert the given keys to real keys
    let privateKey = await this.EcdsaConvertKey(b64PrivateKey);

    // 2.) sign the data with the live key
    let signature = await this.#crypto.subtle.sign({"name": "ECDSA", "hash": {"name": "SHA-256"}}, privateKey, this.base64ToArray(b64data));

    // 3.) Base64 and return our data...
    return  await this.arrayToBase64(new Uint8Array(signature));
  
  };
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcVerifySig (async)
  // What is this: Given a public key, some data, and a signature; prove the
  //               signature came from the data and the public key
  //
  // Arguments:    base64PublicKey: string;
  //               data: Uint8Array;
  //
  // Returns:      base64 encoded signature
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcVerifySig = async (b64PublicKey, b64Signature, b64data) => {
    await this.#sleep(0);

    // 1.) convert the given keys to real keys
    let publicKey = await this.EcdsaConvertKey(b64PublicKey);
    

    // 2.) Convert the signature to an array
    let signature = this.base64ToArray(b64Signature);

    // 3.) verify the data with the live key
    return await this.#crypto.subtle.verify({"name": "ECDSA", "hash": {"name": "SHA-256"}}, publicKey, signature, this.base64ToArray(b64data));

  };
  
  
  
  
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EzConvertKey (base64key)
  // What is this: Sloppy AF function to try converting random data into a key
  //               until something works...
  //
  // Arguments:    none
  //
  // Returns:      hopefully a live key...probably an error and an hour of debugging.
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  
  
  EcdhConvertKey = async (unknown_key) => {
    await this.#sleep(0);

    let key;
    let longKey;
    
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // NATURAL KEY
    if(unknown_key instanceof this.#crypto.CryptoKey){
      return unknown_key;
    }
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // SPKI PUBLIC?
    //
    //
    try {
      key = await this.#crypto.subtle.importKey(
        "spki",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;

    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC
    //
    //
    try {
      key = await this.#crypto.subtle.importKey(
        "raw",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;
      
    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // PKCS8 PRIVATE
    //
    //
    try{
      key = await this.#crypto.subtle.importKey(
        "pkcs8",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey","deriveBits"]
      );
      return key;
      
    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC - PERVERTED
    //
    //
    try {
      
      longKey = new Uint8Array([4].concat(Array.from(this.base64ToArray(unknown_key))));
      key = await this.#crypto.subtle.importKey(
        "raw",
        longKey,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;
      
    } catch(e){
      throw new Error("UNRECOGNIZED KEY FORMAT");
    }



  }




  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcdsaConvertKey (some sort of key)
  // What is this: Sloppy AF function to try converting random data into a key
  //               until something works...
  //
  // Arguments:    none
  //
  // Returns:      hopefully a live key...probably an error and an hour of debugging.
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  EcdsaConvertKey = async (unknown_key) => {
    await this.#sleep(0);

    let key;
    let longKey;
    let err = true;
    
    
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // NATURAL KEY
    if(unknown_key instanceof this.#crypto.CryptoKey){
      return unknown_key;
    }
    
    
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // SPKI PUBLIC?
    //
    //
    try {
      
      key = await this.#crypto.subtle.importKey(
        "spki",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );
      
      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC
    //
    //
    try {
      
      key = await this.#crypto.subtle.importKey(
        "raw",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );

      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // PKCS8 PRIVATE
    //
    //
    try{

      key = await this.#crypto.subtle.importKey(
        "pkcs8",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );

      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC - PERVERTED
    //
    //
    try {

      longKey = new Uint8Array([4].concat(Array.from(this.base64ToArray(unknown_key))));
      key = await this.#crypto.subtle.importKey(
        "raw",
        longKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      );

      return key;
      
    } catch(e){
      throw new Error("UNRECOGNIZED KEY FORMAT");
    }

  }

  
  
}
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\