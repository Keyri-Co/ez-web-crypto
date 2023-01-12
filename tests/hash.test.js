import EZCrypto from "../index";
const ezcrypto = new EZCrypto;

test("simple hash testing", async () => {
    expect(await ezcrypto.HASH("SHA-256","data")).toBe("Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc=");
});
