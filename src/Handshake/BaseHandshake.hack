namespace TLS;

use namespace HH\Lib\Str;

abstract class BaseHandshake implements IHandshake {

  protected ?string $payload;
  protected ?int $length;
  protected bool $ready = false;

  final public function getPayload(): string {
    invariant($this->ready, 'Tried to fetch payload before it was ready');
    return $this->payload as nonnull;
  }

  final public static function unpack(Record::TRecord $record): this {
    invariant(
      $record['type'] === RecordType::HANDSHAKE,
      'Recevied non-handshake payload'
    );

    $handshake_header = Str\slice($record['payload'], 0, 4);
    $handshake_type = \unpack('C', $handshake_header[0])[1]
      |> HandshakeType::assert($$);
    invariant(
      $handshake_type === static::getHandshakeType(),
      'Received the wrong type of handshake',
    );

    return static::unpackImpl($record['payload']);
  }

  abstract public static function unpackImpl(string $payload): this;

  abstract protected static function getHandshakeType(): HandshakeType;

}