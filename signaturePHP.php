<?php
// Define the key pair
$publicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
$privateKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

function base_decode($source_encoding) {
  $source_base = 58;
  $base_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  
  // Build the base-alphabet to integer value map
  $base_map = array_flip(str_split($base_alphabet));

  // Skip and count zero-byte values in the sourceEncoding
  $source_offset = 0;
  $zeroes = 0;
  $decoded_length = 0;
  while ($source_encoding[$source_offset] == $base_alphabet[0]) {
      $zeroes++;
      $source_offset++;
  }

  // Allocate the decoded byte array
  $base_contraction_factor = log($source_base) / log(256);
  $decoded_size = intval(((strlen($source_encoding) - $source_offset) * $base_contraction_factor) + 1);
  $decoded_bytes = array_fill(0, $decoded_size, 0);

  // Perform base-conversion on the source encoding
  while ($source_offset < strlen($source_encoding)) {
      // Process each base-encoded number
      $carry = $base_map[$source_encoding[$source_offset]];

      // Convert the base-encoded number by performing base-expansion
      $i = 0;
      for ($byte_offset = $decoded_size - 1; $byte_offset >= 0; $byte_offset--) {
          if ($carry == 0 && $i >= $decoded_length) {
              break;
          }
          $carry += $source_base * $decoded_bytes[$byte_offset];
          $decoded_bytes[$byte_offset] = $carry % 256;
          $carry = intval($carry / 256);
          $i++;
      }

      $decoded_length = $i;
      $source_offset++;
  }

  // Skip leading zeros in the decoded byte array
  $decoded_offset = $decoded_size - $decoded_length;
  while ($decoded_offset < $decoded_size && $decoded_bytes[$decoded_offset] == 0) {
      $decoded_offset++;
  }

  // Create the final byte array that has been base-decoded
  $final_bytes = array_merge(array_fill(0, $zeroes, 0), array_slice($decoded_bytes, $decoded_offset));

  return $final_bytes;
}

// Decode the private key
$sourceEncodingPrivate = substr($privateKeyMultibase, 1);
$decodedBytesPrivate = base_decode($sourceEncodingPrivate);
$privateKey = implode(array_map("chr", $decodedBytesPrivate));
$private_key_r = substr($privateKey, 2, 34);

// Decode the public key
$sourceEncodingPublic = substr($publicKeyMultibase, 1);
$decodedBytesPublic = base_decode($sourceEncodingPublic);
$publicKey = implode(array_map("chr", $decodedBytesPublic));
$public_key_r = substr($publicKey, 2, 34);

//making keypair
$keypair = $private_key_r . $public_key_r;

if (strlen($keypair) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
  throw new Exception("Invalid keypair length");
}

// Sign the message
$message = "Hello, world!";
$signature = sodium_crypto_sign_detached($message, $keypair);
echo bin2hex($signature);

// Verify the signature
if (sodium_crypto_sign_verify_detached($signature, $message, $public_key_r)) {
    echo "Signature is valid.\n";
} else {
    echo "Invalid signature.\n";
}
