namespace TLS;

use namespace HH\Lib\{C, Str};

final class ServerHello extends BaseHandshake {

  private ?Cipher $cipherSuite;
  private ?string $serverRandom;
  private ?string $sessionID;
  private vec<BaseExtension::TValue> $extensions = vec[];

  protected static function getHandshakeType(): HandshakeType {
    return HandshakeType::SERVER_HELLO;
  }

  public function pack(): void {
    invariant(
      !$this->ready,
      'This payload has already been packed.'
    );
    $this->ready = true;
  }

  /**
   * Payload per RFC 8446:
   *
   *  struct {
   *    ProtocolVersion legacy_version = 0x0303;
   *    Random random;
   *    opaque legacy_session_id_echo<0..32>;
   *    CipherSuite cipher_suite;
   *    uint8 legacy_compression_method = 0;
   *    Extension extensions<6..2^16-1>;
   *  } ServerHello;
   *
   */
  public static function unpackImpl(string $payload): this {
    $instance = new self();
    $instance->payload = $payload;
    $instance->length = Str\length($payload);

    $header = Str\slice($payload, 0, 4);
    $payload = Str\slice($payload, 4);

    // Protocol Version
    // We tell lies to the middleware boxes and fake this being TLS v1.2
    $version = Str\slice($payload, 0, 2);
    invariant(
      $version === "\x03\x03",
      'Recevied a handshake version other than TLS 1.2',
    );
    $payload = Str\slice($payload, 2);

    // Random
    $server_random = Str\slice($payload, 0, 32);
    $instance->serverRandom = $server_random;
    $payload = Str\slice($payload, 32);

    // Session ID
    $session_id = Str\slice($payload, 1, 32);
    $instance->sessionID = $session_id;
    $payload = Str\slice($payload, 33);

    // CipherSuite
    $cipher_suite = Str\slice($payload, 0, 2)
      |> \unpack('n', $$)[1]
      |> Cipher::assert($$);

    $instance->cipherSuite = $cipher_suite;
    $payload = Str\slice($payload, 2);

    // Compression Method
    $compression_method = Str\slice($payload, 0, 1) |> \unpack('C', $$)[1];
    invariant($compression_method === 0, 'Payload must be uncompressed');
    $payload = Str\slice($payload, 1);

    // Extensions
    $extensions_length = Str\slice($payload, 0, 2) |> \unpack('n', $$)[1];
    $payload = Str\slice($payload, 2);

    $extensions_payload = Str\slice($payload, 0, $extensions_length);
    $payload = Str\slice($payload, $extensions_length);

    $extensions = ExtensionParser::parse($extensions_payload);
    $instance->extensions = $extensions;

    foreach ($extensions as $extension) {
      if ($extension['type'] === ExtensionType::KEY_SHARE) {
        $server_public_key =
          Shapes::at($extension['parsed_payload'], 'public_key') as string;
        Auth::setServerPublicKey($server_public_key);
      }
    }

    $instance->ready = true;
    return $instance;
  }

}