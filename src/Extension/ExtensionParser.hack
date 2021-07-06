namespace TLS;

use namespace HH\Lib\{Str, Vec};

abstract final class ExtensionParser {

  const type TRawExtension = shape(
    'type' => ExtensionType,
    'payload' => string,
  );

  public static function parse(
    string $extensions_payload,
  ): vec<BaseExtension::TValue> {
    $raw_extensions = self::splitAll($extensions_payload);
    return Vec\map(
      $raw_extensions,
      $raw_extension ==> self::parseExtension($raw_extension),
    );
  }

  private static function splitAll(
    string $full_payload,
  ): vec<self::TRawExtension> {
    $extensions = vec[];
    while (!Str\is_empty($full_payload)) {
      $extension_type = Str\slice($full_payload, 0, 2)
        |> \unpack('n', $$)[1]
        |> ExtensionType::assert($$);
      $extension_length = Str\slice($full_payload, 2, 2)
        |> \unpack('n', $$)[1];
      // Add 4 because of the header
      $payload = Str\slice($full_payload, 0, $extension_length + 4);
      $extensions[] = shape(
        'type' => $extension_type,
        'payload' => $payload,
      );
      // Add 5 to account for five bytes in the header
      $full_payload = Str\slice($full_payload, $extension_length + 4);
    }
    return $extensions;
  }

  private static function parseExtension(
    self::TRawExtension $extension,
  ): BaseExtension::TValue {
    $type = $extension['type'];
    switch ($type) {
      case ExtensionType::KEY_SHARE:
        $extension_class = KeyShare::class;
        break;
      case ExtensionType::SUPPORTED_VERSIONS:
        $extension_class = SupportedVersions::class;
        break;
    }
    return $extension_class::parse($extension['payload']);
  }

}