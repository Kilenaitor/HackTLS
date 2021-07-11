namespace TLS;

use namespace HH\Lib\Str;

final class Crypto {

  private static ?Crypto $instance;

  const IV_LENGTH = 12;

  private ?string $sharedSecret;
  private ?string $clientHandshakeKey;
  private ?string $clientHandshakeIV;
  private ?string $serverHandshakeKey;
  private ?string $serverHandshakeIV;
  private int $timesDecrypted = 0;

  public static function get(): this {
    if (self::$instance is null) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  public function calculateHandshakeKeys(
    string $client_hello_payload,
    string $server_hello_payload,
  ): void {
    invariant(
      $this->sharedSecret is null
      && $this->clientHandshakeKey is null
      && $this->clientHandshakeIV is null
      && $this->serverHandshakeKey is null
      && $this->serverHandshakeIV is null,
      'Handshake Keys have already been calculated',
    );

    $shared_secret = \sodium_crypto_scalarmult(
      Auth::getClientPrivateKey(),
      Auth::getServerPublicKey()
    );
    $this->sharedSecret = $shared_secret;

    $hello_hash = \hash(
      'sha256',
      $client_hello_payload.$server_hello_payload,
      true, /* binary output */
    );
    $empty_hash = \hash('sha256', '', true /* binary output */);

    $early_secret = HKDF::extract(
      'sha256',
      Str\repeat("\x0", Str\length($empty_hash)),
      0,
      "\x0",
    );
    $derived_secret = HKDF::expandLabel(
      'sha256',
      $early_secret,
      32,
      $empty_hash,
      'derived',
    );
    $handshake_secret = HKDF::extract(
      'sha256',
      $shared_secret,
      0,
      $derived_secret,
    );

    $client_handshake_traffic_secret = HKDF::expandLabel(
      'sha256',
      $handshake_secret,
      32,
      $hello_hash,
      'c hs traffic',
    );
    $server_handshake_traffic_secret = HKDF::expandLabel(
      'sha256',
      $handshake_secret,
      32,
      $hello_hash,
      's hs traffic',
    );

    $this->clientHandshakeKey = HKDF::expandLabel(
      'sha256',
      $client_handshake_traffic_secret,
      16,
      '',
      'key',
    );
    $this->serverHandshakeKey = HKDF::expandLabel(
      'sha256',
      $server_handshake_traffic_secret,
      16,
      '',
      'key',
    );

    $this->clientHandshakeIV = HKDF::expandLabel(
      'sha256',
      $client_handshake_traffic_secret,
      12,
      '',
      'iv',
    );
    $this->serverHandshakeIV = HKDF::expandLabel(
      'sha256',
      $server_handshake_traffic_secret,
      12,
      '',
      'iv',
    );
  }

  public function decryptApplicationData(
    Record::TRecord $application_data,
  ): string {
    $server_handshake_key = $this->serverHandshakeKey;
    invariant(
      $server_handshake_key is nonnull,
      'Tried to decrypt payload before key exchange finished'
    );

    $server_handshake_iv = $this->getServerHandshakeIV();

    $wrapper = $application_data['payload'];
    $payload_length = Str\length($wrapper);
    $encrypted_data = Str\slice($wrapper, 0, $payload_length - 16);
    $auth_tag = Str\slice($wrapper, $payload_length - 16);
    $record_data = \pack('C', $application_data['type'])
      . $application_data['version']
      . \pack('n', $payload_length);

    $decrypted_wrapper = \openssl_decrypt(
      $encrypted_data,
      "aes-128-gcm",
      $server_handshake_key,
      \OPENSSL_RAW_DATA,
      $server_handshake_iv,
      $auth_tag,
      $record_data,
    );
    invariant($decrypted_wrapper !== false, 'Failed to decrypt server payload');

    return $decrypted_wrapper;
  }

  private function getServerHandshakeIV(): string {
    $server_handshake_iv = $this->serverHandshakeIV;
    invariant(
      $server_handshake_iv is nonnull,
      'Tried to decrypt payload before key exchange finished',
    );

    for ($i = 0; $i < 8; $i++) {
      $server_handshake_iv[self::IV_LENGTH - 1 - $i] = \chr(
        \ord($server_handshake_iv[self::IV_LENGTH - 1 - $i]) ^
          (($this->timesDecrypted >> ($i * 8)) & 0xFF),
      );
    }

    $this->timesDecrypted++;
    return $server_handshake_iv;
  }

  // TODO: Need to xor the IV every time we use it to decode a payload

}