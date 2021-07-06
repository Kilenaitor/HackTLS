namespace TLS;

use namespace HH\Lib\Str;

abstract final class SupportedVersions extends BaseExtension {

  <<__Override>>
  public static function getPayload(): string {
    return '';
  }

  <<__Override>>
  public static function parse(string $raw_payload): this::TValue {
    $extension_type = Str\slice($raw_payload, 0, 2) |> \unpack('n', $$)[1];
    invariant(
      $extension_type === ExtensionType::SUPPORTED_VERSIONS,
      'Can only parse a key share extension payload',
    );
    $payload = Str\slice($raw_payload, 2);

    $length = Str\slice($payload, 0, 2);
    $payload = Str\slice($payload, 2);

    $version = Str\slice($payload, 0, 2);
    invariant(
      $version === "\x03\x04",
      'Supported Version must equal TLS v1.3',
    );

    return shape(
      'type' => ExtensionType::SUPPORTED_VERSIONS,
      'raw_payload' => $payload,
      'parsed_payload' => shape(
        'version' => $version,
      ),
    );
  }

}