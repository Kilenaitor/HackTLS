namespace TLS;

use namespace HH\Lib\TCP;

final class CloseableSocket {
  public function __construct(
    private TCP\CloseableSocket $socket,
  ) {}

  public async function writeAllAsync(
    string $data,
    ?int $timeout_ns = null,
  ): Awaitable<void> {
    return await $this->socket->writeAllAsync($data, $timeout_ns);
  }

  public async function writeAllowPartialSuccessAsync(
    string $bytes,
    ?int $timeout_ns = null,
  ): Awaitable<int> {
    return await $this->socket->writeAllowPartialSuccessAsync(
      $bytes,
      $timeout_ns,
    );
  }

  public async function readAllAsync(
    ?int $max_bytes = null,
    ?int $timeout_ns = null,
  ): Awaitable<string> {
    return await $this->socket->readAllAsync($max_bytes, $timeout_ns);
  }

  public async function readFixedSizeAsync(
    int $size,
    ?int $timeout_ns = null,
  ): Awaitable<string> {
    return await $this->socket->readFixedSizeAsync($size, $timeout_ns);
  }
}