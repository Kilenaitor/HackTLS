<<__EntryPoint>>
async function main(): Awaitable<void> {
  require('vendor/autoload.hack');
  \Facebook\AutoloadMap\initialize();

  $socket = await TLS\connect_async('gateway.discord.gg');

  $nonce = HH\Lib\SecureRandom\string(20) |> base64_encode($$);
  $request = <<<EOF
GET /?v=9&encoding=json HTTP/1.1
Host: gateway.discord.gg
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: $nonce
Sec-WebSocket-Version: 13
\n
EOF;

  $request_length = HH\Lib\Str\length($request);
  $bytes_written = await $socket->writeAllowPartialSuccessAsync($request);
  if ($bytes_written !== $request_length) {
    die('Unable to write message to socket');
  }

  $response = await $socket->readAllAsync();
  var_dump($response);
}
