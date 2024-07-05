<?php
function base_encode($bytes, $target_base, $base_alphabet) {
    $zeroes = 0;
    $length = 0;
    $begin = 0;
    $end = count($bytes);

    // count the number of leading bytes that are zero
    while ($begin != $end && $bytes[$begin] == 0) {
        $begin++;
        $zeroes++;
    }

    // allocate enough space to store the target base value
    $base_expansion_factor = log(256) / log($target_base);
    $size = intval(($end - $begin) * $base_expansion_factor + 1);
    $base_value = array_fill(0, $size, 0);

    // process the entire input byte array
    while ($begin != $end) {
        $carry = $bytes[$begin];

        // for each byte in the array, perform base-expansion
        $i = 0;
        for ($base_position = $size - 1; $base_position >= 0; $base_position--) {
            if ($carry == 0 && $i >= $length) {
                break;
            }
            $carry += 256 * $base_value[$base_position];
            $base_value[$base_position] = $carry % $target_base;
            $carry = intval($carry / $target_base);
            $i++;
        }

        $length = $i;
        $begin++;
    }

    // skip leading zeroes in base-encoded result
    $base_encoding_position = $size - $length;
    while ($base_encoding_position != $size && $base_value[$base_encoding_position] == 0) {
        $base_encoding_position++;
    }

    // convert the base value to the base encoding
    $base_encoding = str_repeat($base_alphabet[0], $zeroes);
    for ($base_encoding_position; $base_encoding_position < $size; $base_encoding_position++) {
        $base_encoding .= $base_alphabet[$base_value[$base_encoding_position]];
    }

    return $base_encoding;
}

// Example hexadecimal input
$hex_input = '8026c96ef9ea10c5e414c471723aff9de72c35fa5b70fae97e8832ecac7d2e2b8ed6';
$bytes_input = hex2bin($hex_input);
$base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
$base58_encoded = "z" . base_encode(array_values(unpack('C*', $bytes_input)), 58, $base58_alphabet);

echo $base58_encoded;

?>