import EZCrypto from "../index";
const ezcrypto = new EZCrypto;

test("AESMakeKey - NOT EXTRACTABLE", async () => {
    
    let aesKey = await ezcrypto.AESMakeKey(false);
    expect(aesKey instanceof String).toBe(false);
    expect(aesKey?.type).toBe("secret");
    expect(aesKey?.extractable).toBe(false);
    expect(aesKey?.algorithm?.name).toBe("AES-GCM");

});


test("AESMakeKey - is extractable", async () => {
    
    let aesKey = await ezcrypto.AESMakeKey(true);
    
    expect(aesKey instanceof String).toBe(false);

});
