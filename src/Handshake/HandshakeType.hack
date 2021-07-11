namespace TLS;

enum HandshakeType: int as int {
  HELLO_REQUEST = 0;
  CLIENT_HELLO = 1;
  SERVER_HELLO = 2;
  ENCRYPTED_EXTENSIONS = 8;
  CERTIFICATE = 11;
  SERVER_KEY_EXCHANGE = 12;
  CERTIFICATE_REQUEST = 13;
  SERVER_HELLO_DONE = 14;
  CERTIFICATE_VERIFY = 15;
  CLIENT_KEY_EXCHANGE = 16;
  FINISHED = 20;
}
