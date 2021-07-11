namespace TLS;

use namespace HH\Lib\{C, Keyset, Network, SecureRandom, Str, TCP};

abstract final class Record {

  const type TRecord = shape(
    'type' => RecordType,
    'version' => string,
    'payload' => string,
  );

  /**
   * Some records are sent back-to-back. Convenience function to take
   * an arbitrary number of concatenated records and split them up.
   */
  public static function splitAll(string $raw_payload): vec<self::TRecord> {
    $records = vec[];
    while (!Str\is_empty($raw_payload)) {
      $header = Str\slice($raw_payload, 0, 5);
      $record_type = \unpack('C', $header[0])[1]
        |> RecordType::assert($$);
      $version = Str\slice($header, 1, 2);
      $length = Str\slice($header, 3, 2) |> \unpack('n', $$)[1] as int;
      $payload = Str\slice($raw_payload, 5, $length);
      $records[] = shape(
        'type' => $record_type,
        'version' => $version,
        'payload' => $payload,
      );
      // Add 5 to account for five bytes in the header
      $raw_payload = Str\slice($raw_payload, $length + 5);
    }
    return $records;
  }

  public static function addHeader(
    RecordType $type,
    TLSVersion $version,
    string $payload,
  ): string {
    return \pack('C', $type).
      \pack('n', $version).
      \pack('n', Str\length($payload)).
      $payload;
  }

  public static function stripHeader(string $payload): string {
    return Str\slice($payload, 5);
  }
}

enum RecordType: int as int {
  INVALID = 0;
  CHANGE_CIPHER_SPEC = 20;
  ALERT = 21;
  HANDSHAKE = 22;
  APPLICATION_DATA = 23;
}

enum TLSVersion: int as int {
  V1_0 = 0x0301;
  V1_1 = 0x0302;
  V1_2 = 0x0303;
  V1_3 = 0x0304;
}
