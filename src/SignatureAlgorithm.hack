namespace TLS;

enum SignatureAlgorithm: int as int {
  // OpenSSL
  SHA1_RSA = 0x0201;
  SHA256_RSA = 0x0401;
  SHA384_RSA = 0x0501;
  SHA512_RSA = 0x0601;
  SHA256_ECDSA = 0x0403;
  SHA384_ECDSA = 0x0503;
  SHA512_ECDSA = 0x0603;
  SHA256_RSAE = 0x0804;
  SHA384_RSAE = 0x0805;
  SHA512_RSAE = 0x0806;
  SHA256_PSS = 0x0809;
  SHA384_PSS = 0x080a;
  SHA512_PSS = 0x080b;
  // LibSodium
  ED25519 = 0x0807;
}