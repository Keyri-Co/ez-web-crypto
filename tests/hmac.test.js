import EZCrypto from "../index";
const ezcrypto = new EZCrypto;

test("simple hmac testing", async () => {
    expect(await ezcrypto.HMAC("secret","data")).toBe("1b2c16b75bd2a870c114153ccda5bcfca63314bc722fa160d690de133ccbb9db");
});
