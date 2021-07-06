namespace TLS;

use namespace HH\Lib\Str;

abstract final class Auth {

  private static ?string $clientPrivateKey;
  private static ?string $clientPublicKey;
  private static ?string $serverPrivateKey;
  private static ?string $serverPublicKey;

  public static function init(): void {
    $kx_keypair = \sodium_crypto_kx_keypair();
    self::$clientPrivateKey = \sodium_crypto_kx_secretkey($kx_keypair);
    self::$clientPublicKey = \sodium_crypto_kx_publickey($kx_keypair);
  }

  public static function getClientPrivateKey(): string {
    if (self::$clientPrivateKey is null) {
      self::init();
    }
    return self::$clientPrivateKey as nonnull;
  }

  public static function getClientPublicKey(): string {
    if (self::$clientPublicKey is null) {
      self::init();
    }
    return self::$clientPublicKey as nonnull;
  }

  public static function setServerPublicKey(
    string $public_key,
  ): void {
    self::$serverPublicKey = $public_key;
  }

  public static function getServerPublicKey(): string {
    invariant(
      self::$serverPublicKey is nonnull,
      'Tried to access server public key before set by ServerHello handshake',
    );
    return self::$serverPublicKey as nonnull;
  }

}