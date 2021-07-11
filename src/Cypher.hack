namespace TLS;

enum Cipher: int as int {
  AES_128_GCM = 0x1301;
  AES_256_GCM = 0x1302;
  CHACHA20_POLY1305 = 0x1303;
  AES_128_CCM = 0x1304;
}

enum CipherKey: int as int {
  AES_128_GCM = 9;
  AES_256_GCM = 32;
  CHACHA20_POLY1305 = 93;
  AES_128_CCM = 14;
}
