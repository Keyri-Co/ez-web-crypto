import EZCrypto from "../index";
const ezcrypto = new EZCrypto;

test("everything should work test", async () => {
    
    let str = "Hello, 世界!".repeat(10_000);
    let strAry = new TextEncoder().encode(str);

    let b64str = ezcrypto.arrayToBase64(strAry);
    let strAry2 = ezcrypto.base64ToArray(b64str);

    let strOut = new TextDecoder().decode(strAry2);

    // TEST 1 - Base64 in and out...
    expect(str).toBe(strOut);


    let password = "Blumpkin!";
    let secret = b64str;
    
    let pwdEncrypted = await ezcrypto.PASSWORD_ENCRYPT(password, btoa(secret));
    let pwdDecrypted = await ezcrypto.PASSWORD_DECRYPT(password, pwdEncrypted);

    // TEST 2 - 
    expect(secret).toBe(pwdDecrypted);


    let aesKeyStr = await ezcrypto.AESMakeKey(true);
    let aesKey = await ezcrypto.AESImportKey(aesKeyStr);
    let aesEncrypted = await ezcrypto.AESEncrypt(aesKey, btoa(secret));
    let aesDecrypted = await ezcrypto.AESDecrypt(aesKey, aesEncrypted.iv, aesEncrypted.ciphertext, true);

    // TEST 3 -
    expect(secret).toBe(aesDecrypted);


    const ecdhKeys = await ezcrypto.EcMakeCryptKeys();
    let ecEncrypted = await ezcrypto.EcEncrypt(ecdhKeys.privateKey, ecdhKeys.publicKey, secret);
    let ecDecrypted = await ezcrypto.EcDecrypt(ecdhKeys.privateKey, ecdhKeys.publicKey, ecEncrypted.iv, ecEncrypted.ciphertext, true);

    // TEST 4 -
    expect(str).toBe(ecDecrypted);
    

    let hkdfEncrypted = await ezcrypto.HKDFEncrypt(ecdhKeys.privateKey, ecdhKeys.publicKey, secret);
    let hkdfDecrypted = await ezcrypto.HKDFDecrypt(ecdhKeys.privateKey, ecdhKeys.publicKey, hkdfEncrypted.salt, hkdfEncrypted.iv, hkdfEncrypted.ciphertext, true);

    // TEST 5 -
    expect(str).toBe(hkdfDecrypted);

  /*
    EcMakeSigKeys(exportable?: boolean): Promise<{ publicKey: string; privateKey: string | CryptoKey }>;
    EcSignData(b64PrivateKey: string, b64data: string): Promise<string>;
    EcVerifySig(
      b64PublicKey: string,
      b64Signature: string,
      b64data: string
    ): Promise<boolean>;


    */
});