namespace TLS;

use namespace HH\Lib\Str;

/**
  * Hack doesn't have hash_hkdf like PHP does.
  * This is a userland implementation of that function.
  */
abstract final class HKDF {

  public static function extract(
    string $algorithm,
    string $key,
    int $length = 0,
    string $salt = '',
  ): string {
    $algorithm_length = Str\length(\hash($algorithm, ''));
    if ($length === 0) {
      $length = $algorithm_length;
    }
    if (Str\is_empty($salt)) {
      $algorithm_length = Str\length(\hash($algorithm, ''));
      $salt = Str\repeat("\x0", $algorithm_length);
    }
    return \hash_hmac($algorithm, $key, $salt, /* raw_output */ true);
  }

  public static function expand(
    string $algorithm,
    string $secret,
    int $length = 0,
    string $info = '',
    string $salt = '',
  ): string {
    $algorithm_length = Str\length(\hash($algorithm, ''));
    if ($length === 0) {
      $length = $algorithm_length;
    }

    $okm = '';
    for (
      $key_block = '', $block_index = 1;
      Str\length($okm) < $length;
      $block_index++
    ) {
			$key_block = \hash_hmac(
        $algorithm,
        $key_block.$info.\chr($block_index),
        $secret,
        true, // raw_output
      );
			$okm .= $key_block;
		}
    return Str\slice($okm, 0, $length);
  }

  public static function expandLabel(
    string $algorithm,
    string $secret,
    int $length = 0,
    string $info = '',
    string $label = '',
    string $salt = '',
  ): string {
    $algorithm_length = Str\length(\hash($algorithm, ''));
    if ($length === 0) {
      $length = $algorithm_length;
    }

    $label = "tls13 $label";
    $info = \pack('n', $length)
      . \pack('C', Str\length($label)).$label
      . \pack('C', Str\length($info)).$info;
    return self::expand(
      $algorithm,
      $secret,
      $length,
      $info,
      $salt,
    );
  }
}