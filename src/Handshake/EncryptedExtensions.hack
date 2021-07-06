namespace TLS;

use namespace HH\Lib\{C, Keyset, SecureRandom, Str};

final class EncryptedExtensions extends BaseHandshake {

  protected static function getHandshakeType(): HandshakeType {
    return HandshakeType::ENCRYPTED_EXTENSIONS;
  }

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
  }

  <<__Memoize>>
  public function pack(): void {
  }

}