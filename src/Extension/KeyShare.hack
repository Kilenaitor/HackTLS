namespace TLS;

use namespace HH\Lib\Str;

abstract final class KeyShare extends BaseExtension {

  <<__Override>>
  public static function getPayload(): string {
    return '';
  }

  <<__Override>>
  public static function parse(string $raw_payload): this::TValue {
    $extension_type = Str\slice($raw_payload, 0, 2) |> \unpack('n', $$)[1];
    invariant(
      $extension_type === ExtensionType::KEY_SHARE,
      'Can only parse a key share extension payload',
    );
    $payload = Str\slice($raw_payload, 4);

    $exchange_algorithm = Str\slice($payload, 0, 2);
    $payload = Str\slice($payload, 2);

    $length = Str\slice($payload, 0, 2);
    $payload = Str\slice($payload, 2);

    $public_key = $payload;
    return shape(
      'type' => ExtensionType::KEY_SHARE,
      'raw_payload' => $payload,
      'parsed_payload' => shape(
        'public_key' => $public_key,
      ),
    );
  }

}