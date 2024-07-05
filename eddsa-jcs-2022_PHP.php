<?php

// Define the key pair
//$public_key_multibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
//$private_key_multibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";


$keypair = sodium_crypto_sign_keypair();

// Extract the private and public keys
$private_key = sodium_crypto_sign_secretkey($keypair);
$public_key = sodium_crypto_sign_publickey($keypair);


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
$sourceEncodingPrivate = substr($private_key_multibase, 1);
$decodedBytesPrivate = base_decode($sourceEncodingPrivate);
$privateKey = implode(array_map("chr", $decodedBytesPrivate));
$private_key_r = substr($privateKey, 2, 34);

// Decode the public key
$sourceEncodingPublic = substr($public_key_multibase, 1);
$decodedBytesPublic = base_decode($sourceEncodingPublic);
$publicKey = implode(array_map("chr", $decodedBytesPublic));
$public_key_r = substr($publicKey, 2, 34);

//making keypair
$keypair = $private_key_r . $public_key_r;

if (strlen($keypair) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
  throw new Exception("Invalid keypair length");
}

// canonicalization function
function json_sort($json_data) {
  ksort($json_data);
  foreach ($json_data as $key => $value) {
      if (is_array($json_data[$key])) {
          $json_data[$key] = json_sort($json_data[$key]);
      }
  }
  return $json_data;
}

// Load the document
$document = '{
  "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
      "id": "did:example:abcdefgh",
      "alumniOf": "The School of Examples"
  }
}';

// Canonize the document
$cannon = json_encode(json_sort(json_decode($document,true)), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK | JSON_PRESERVE_ZERO_FRACTION | JSON_BIGINT_AS_STRING);

// Hash canonized document
$doc_hash = hash('sha256', $cannon, true);
echo bin2hex($doc_hash) . "\n";

// Set proof options
$proof_config = '{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "2023-02-24T23:36:38Z",
  "verificationMethod": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "proofPurpose": "assertionMethod"
}';

// Canonize the proof config
$proof_canon=json_encode(json_sort(json_decode($proof_config,true)), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK | JSON_PRESERVE_ZERO_FRACTION | JSON_BIGINT_AS_STRING);

// Hash canonized proof config
$proof_hash = hash('sha256', $proof_canon, true);
echo bin2hex($proof_hash) . "\n";

// Combine hashes
$combined_hash = $proof_hash . $doc_hash;
echo bin2hex($combined_hash) . "\n";

// Sign
$signature = sodium_crypto_sign_detached($combined_hash, $keypair);
echo bin2hex($signature) . "\n";

// Verify (just to see we have a good private/public pair)
$result = sodium_crypto_sign_verify_detached($signature, $combined_hash, $public_key_r);
var_dump($result);

// Construct Signed Document
$signed_document = json_decode($document,true);
$proof_config_array = json_decode($proof_config,true);
unset($proof_config_array['@context']);
$proof_config_array["proofValue"] = base64_encode($signature);
$signed_document["proof"] = $proof_config_array;

echo json_encode($signed_document, JSON_PRETTY_PRINT);
