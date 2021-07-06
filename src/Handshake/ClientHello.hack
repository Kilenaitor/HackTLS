namespace TLS;

use namespace HH\Lib\{C, Keyset, SecureRandom, Str};

final class ClientHello extends BaseHandshake {

  private string $host;

  public function __construct(string $host) {
    $this->host = $host;
    $this->pack();
  }

  protected static function getHandshakeType(): HandshakeType {
    return HandshakeType::CLIENT_HELLO;
  }

  public static function unpackImpl(string $payload): this {
    $host = 'testtesttest.com';
    return new self($host);
  }

  <<__Memoize>>
  public function pack(): void {
    // We have to build it inside-out to include the payload lengths
    $this->payload = $this->getExtensionsPayload();

    // Compression Method
    $this->prepend(\pack('n', 0x0100));

    // Cipher Suites
    $this->prepend($this->getCipherSuites());

    // Session
    $this->prepend(\pack('C', 32).SecureRandom\string(32));

    // Client Random
    $this->prepend(SecureRandom\string(32));

    // Client Version; SSL v3.3 aka TLS v1.2
    // We lie and say it's TLS v1.2 because of incompatible middleware.
    $this->prepend(\pack('n', 0x0303));

    // Handshake Header
    \pack('C', 0x01).\pack('xn', Str\length($this->payload as nonnull))
      |> $this->prepend($$);

    $this->ready = true;
  }

  private function prepend(string $data): this {
    $this->payload = $data.$this->payload;
    return $this;
  }

  private function getCipherSuites(): string {
    $all_cipher_methods = \openssl_get_cipher_methods();
    $tls_ciphers = Keyset\intersect(
      Keyset\keys($all_cipher_methods),
      keyset[
        CipherKey::AES_128_GCM,
        CipherKey::AES_256_GCM,
        CipherKey::CHACHA20_POLY1305,
        CipherKey::AES_128_CCM,
      ],
    );

    $num_ciphers = C\count($tls_ciphers);
    $num_bytes = $num_ciphers * 2; // 2 bytes per cipher

    $ciphers_payload = \pack('n', $num_bytes);
    if (C\contains_key($tls_ciphers, CipherKey::AES_128_GCM)) {
      $ciphers_payload .= \pack('n', Cipher::AES_128_GCM);
    }
    if (C\contains_key($tls_ciphers, CipherKey::AES_256_GCM)) {
      $ciphers_payload .= \pack('n', Cipher::AES_256_GCM);
    }
    if (C\contains_key($tls_ciphers, CipherKey::CHACHA20_POLY1305)) {
      $ciphers_payload .= \pack('n', Cipher::CHACHA20_POLY1305);
    }
    if (C\contains_key($tls_ciphers, CipherKey::AES_128_CCM)) {
      $ciphers_payload .= \pack('n', Cipher::AES_128_CCM);
    }
    return $ciphers_payload;
  }

  private function getExtensionsPayload(): string {
    $extension_payload = $this->getServerName()
      . $this->getSupportedGroups()
      . $this->getSignatureAlgorithms()
      . $this->getKeyShare()
      . $this->getExchangeModes()
      . $this->getSupportedVersions();
    return \pack('n', Str\length($extension_payload)).$extension_payload;
  }

  private function getServerName(): string {
    $hostname_length = Str\length($this->host);
    return \pack('CC', 0x00, 0x00) // Server Name Extension Marker
      . \pack('n', $hostname_length + 5) // extension data length
      . \pack('n', $hostname_length + 3) // entry length
      . \pack('C', 0x00) // entry type (DNS Hostname)
      . \pack('n', $hostname_length) // DNS Hostname length
      . $this->host;
  }

  private function getSupportedGroups(): string {
    return \pack('CC', 0x00, 0x0a) // Supported Groups Extension Marker
      . \pack('n', 8) // extension length
      . \pack('n', 6) // entries length
      . \pack('n', 0x001D) // x25519
      . \pack('n', 0x0018) // secp384r1
      . \pack('n', 0x0019); // secp521r1
  }

  private function getSignatureAlgorithms(): string {
    return \pack('CC', 0x00, 0x0d) // Signature Algorithms Extension Marker
      . \pack('n', 30) // length = payload + 2 bytes
      . \pack('n', 28) // length = 14 algorithms * 2 bytes
      . \pack('n', SignatureAlgorithm::SHA256_ECDSA)
      . \pack('n', SignatureAlgorithm::SHA384_ECDSA)
      . \pack('n', SignatureAlgorithm::SHA512_ECDSA)
      . \pack('n', SignatureAlgorithm::ED25519)
      . \pack('n', SignatureAlgorithm::SHA256_RSA)
      . \pack('n', SignatureAlgorithm::SHA384_RSA)
      . \pack('n', SignatureAlgorithm::SHA512_RSA)
      . \pack('n', SignatureAlgorithm::SHA256_RSAE)
      . \pack('n', SignatureAlgorithm::SHA384_RSAE)
      . \pack('n', SignatureAlgorithm::SHA512_RSAE)
      . \pack('n', SignatureAlgorithm::SHA256_PSS)
      . \pack('n', SignatureAlgorithm::SHA384_PSS)
      . \pack('n', SignatureAlgorithm::SHA512_PSS)
      . \pack('n', SignatureAlgorithm::SHA1_RSA);
  }

  private function getKeyShare(): string {
    return \pack('CC', 0x00, 0x33) // Key Share Extension Marker
      . \pack('n', 38) // Extension Length
      . \pack('n', 36) // Key Share Length
      . \pack('n', 0x001d) // x25519 Exchange
      . \pack('n', 32) // Key size
      . Auth::getClientPublicKey();
  }

  private function getExchangeModes(): string {
    return \pack('CC', 0x00, 0x2d) // PSK Key Exchange Modes Extension Marker
      . \pack('n', 2) // Extension Length
      . \pack('C', 0x01) // Size of Exchange Mode
      . \pack('C', 0x01); // PSK with (EC)DHE key establishment
  }

  private function getSupportedVersions(): string {
    return \pack('C*', 0x00, 0x2b) // Supported Versions Extension
      . \pack('n', 3) // Extension Length
      . \pack('C', 0x02) // 2-byte TLS Version
      . \pack('n', 0x0304); // SSL v3.4 aka TLS v1.3
  }

}