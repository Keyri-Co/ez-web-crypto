declare module "@justinwwolcott/ez-web-crypto" {
    export default class EZCrypto {
      private nodeEnvLoad: () => Promise<void>;
      private sleep: (duration: number) => Promise<void>;
      constructor();
      base64ToArray(strng: string): Uint8Array;
      arrayToBase64(ary: Uint8Array): string;
      HMAC(secret: string, data: string): Promise<string>;
      HASH(algo: string, data: string, len?: number): Promise<string>;
      PASSWORD_ENCRYPT(password: string, base64data: string): Promise<string>;
      PASSWORD_DECRYPT(password: string, base64data: string): Promise<string>;
      AESMakeKey(exportable?: boolean): Promise<string | CryptoKey>;
      AESImportKey(aes_key: string | CryptoKey, exportable?: boolean): Promise<CryptoKey>;
      AESEncrypt(
        base_64_key: string | CryptoKey,
        base_64_data: string,
        base_64_nonce?: boolean
      ): Promise<{ ciphertext: string; iv: string }>;
      AESDecrypt(
        base_64_key: string | CryptoKey,
        base_64_nonce: string,
        base_64_cipher: string,
        returnText?: boolean
      ): Promise<ArrayBuffer | string>;
      EcMakeCryptKeys(exportable?: boolean): Promise<any>;
      EcEncrypt(
        b64Private: string,
        b64Public: string,
        b64data: string
      ): Promise<{ ciphertext: string; iv: string }>;
      EcDecrypt(
        b64Private: string,
        b64Public: string,
        b64Nonce: string,
        b64data: string
      ): Promise<ArrayBuffer>;
      HKDFEncrypt(
        b64Private: string,
        b64Public: string,
        b64data: string
      ): Promise<{ ciphertext: string; salt: string; iv: string }>;
      HKDFDecrypt(
        b64Private: string,
        b64Public: string,
        b64Salt: string,
        b64iv: string,
        b64data: string
      ): Promise<ArrayBuffer>;
      EcMakeSigKeys(exportable?: boolean): Promise<{ publicKey: string; privateKey: string | CryptoKey }>;
      EcSignData(b64PrivateKey: string, b64data: string): Promise<string>;
      EcVerifySig(
        b64PublicKey: string,
        b64Signature: string,
        b64data: string
      ): Promise<boolean>;
      EcdhConvertKey(unknown_key: any): Promise<CryptoKey>;
      EcdsaConvertKey(unknown_key: any): Promise<CryptoKey>;
    }
  }
  