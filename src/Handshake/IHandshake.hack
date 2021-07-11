namespace TLS;

interface IHandshake {

  /**
   * Converts the instance to the binary string for sending down the TCP buffer
   */
  public function pack(): void;

  /**
   * Inits a class instance from a raw payload recived from a server/client
   */
  public static function unpack(Record::TRecord $record): this;

  public function getPayload(): string;
}
