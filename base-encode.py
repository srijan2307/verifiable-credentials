import math

def base_encode(bytes, target_base, base_alphabet):
    zeroes = 0
    length = 0
    begin = 0
    end = len(bytes)

    # count the number of leading bytes that are zero
    while begin != end and bytes[begin] == 0:
        begin += 1
        zeroes += 1

    # allocate enough space to store the target base value
    base_expansion_factor = math.log(256) / math.log(target_base)
    size = int((end - begin) * base_expansion_factor + 1)
    base_value = bytearray(size)

    # process the entire input byte array
    while begin != end:
        carry = bytes[begin]

        # for each byte in the array, perform base-expansion
        i = 0
        for base_position in range(size - 1, -1, -1):
            if carry == 0 and i >= length:
                break
            carry += int(256 * base_value[base_position])
            base_value[base_position] = int(carry % target_base)
            carry = int(carry // target_base)
            i += 1

        length = i
        begin += 1

    # skip leading zeroes in base-encoded result
    base_encoding_position = size - length
    while base_encoding_position != size and base_value[base_encoding_position] == 0:
        base_encoding_position += 1

    # convert the base value to the base encoding
    base_encoding = base_alphabet[0] * zeroes
    for base_encoding_position in range(base_encoding_position, size):
        base_encoding += base_alphabet[base_value[base_encoding_position]]

    return base_encoding

# Example hexadecimal input
hex_input = 'efaa42b4fa102cf044d99f4060b905ff087655d763c085300fc59eaab7f01e8d'
bytes_input = bytearray.fromhex(hex_input)
base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base58_encoded = base_encode(bytes_input, 58, base58_alphabet)
multibase_encoded = 'z' + base58_encoded
print(multibase_encoded)
