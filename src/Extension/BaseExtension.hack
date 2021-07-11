namespace TLS;

abstract class BaseExtension {

  const type TValue = shape(
    'type' => ExtensionType,
    'raw_payload' => string,
    'parsed_payload' => shape(...),
  );

  abstract public static function getPayload(): string;

  abstract public static function parse(string $raw_payload): this::TValue;

}
