import EZCrypto from "../index";
const ezcrypto = new EZCrypto;

test("AESMakeKey", async () => {
    
    let aesKey = await ezcrypto.AESMakeKey(false);

    //todo: expect(aesKey instanceof CryptoKey).toBe(true);
    
    expect(aesKey?.type).toBe("secret");
    expect(aesKey?.extractable).toBe(false);
    expect(aesKey?.algorithm?.name).toBe("AES-GCM");

});
