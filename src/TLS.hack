namespace TLS;

use namespace HH\Lib\{Str, TCP, Vec};

async function connect_async(
  string $host,
  TCP\ConnectOptions $opts = shape(),
): Awaitable<CloseableSocket> {
  $socket = await TCP\connect_async(
    $host,
    443,
    $opts
  );

  echo "Going to say hello to:\n$host\n\n";

  $client_hello = new ClientHello($host);
  $client_hello_payload = Record::addHeader(
    RecordType::HANDSHAKE,
    TLSVersion::V1_0,
    $client_hello->getPayload(),
  );

  $payload_length = Str\length($client_hello_payload);
  $bytes_written =
    await $socket->writeAllowPartialSuccessAsync($client_hello_payload);
  if ($bytes_written !== $payload_length) {
    \die('Unable to write message to socket');
  }

  $response = await $socket->readAllowPartialSuccessAsync();
  $records = Record::splitAll($response);

  // We expect a ServerHello next
  $server_hello = ServerHello::unpack($records[0]);
  Crypto::get()->calculateHandshakeKeys(
    $client_hello->getPayload(),
    $server_hello->getPayload(),
  );

  // No longer needed per the spec but sent to disguise the session
  // as a TLS v1.2 session for middleware compatibility
  $_change_cipher_spec = $records[1];

  // After ServerHello and ChangeCipherSpec it's all ApplicationData
  $application_data_records = Vec\drop($records, 2);
  \print_r($application_data_records);
  foreach ($application_data_records as $encrypted_application_data) {
    $application_data = Crypto::get()->decryptApplicationData(
      $encrypted_application_data,
    );
    echo "Decrypted Wrapper:\n".\bin2hex($application_data)."\n\n";
  }

  // Next handshake is Application Data
  $application_data_encrypted = $records[2];
  $application_data = Crypto::get()->decryptApplicationData(
    $application_data_encrypted,
  );

  // Yay. We've successfully established a shared secret and decrypted
  // the application data payload. Next up is certificate verification
  // and then one more set of keys to compute.

  // 08 00 00 06 00 04 00 00 00 00

  echo "Decrypted Wrapper:\n".\bin2hex($application_data)."\n\n";

  die();

  $private_key = \openssl_pkey_new();
  $public_key_pem = \openssl_pkey_get_details($private_key)['key'];
  $public_key = \openssl_pkey_get_public($public_key_pem);

  // This is a TLS CloseableSocket which is a wrapper around the HSL TCP one
  return new CloseableSocket($socket);
}