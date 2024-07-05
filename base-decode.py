def base_decode(source_encoding, source_base, base_alphabet):
    # Build the base-alphabet to integer value map
    base_map = {char: i for i, char in enumerate(base_alphabet)}

    # Skip and count zero-byte values in the sourceEncoding
    source_offset = 0
    zeroes = 0
    decoded_length = 0
    while source_encoding[source_offset] == base_alphabet[0]:
        zeroes += 1
        source_offset += 1

    # Allocate the decoded byte array
    base_contraction_factor = math.log(source_base) / math.log(256)
    decoded_size = int(((len(source_encoding) - source_offset) * base_contraction_factor) + 1)
    decoded_bytes = bytearray(decoded_size)

    # Perform base-conversion on the source encoding
    while source_offset < len(source_encoding):
        # Process each base-encoded number
        carry = base_map[source_encoding[source_offset]]

        # Convert the base-encoded number by performing base-expansion
        i = 0
        for byte_offset in range(decoded_size - 1, -1, -1):
            if carry == 0 and i >= decoded_length:
                break
            carry += source_base * decoded_bytes[byte_offset]
            decoded_bytes[byte_offset] = carry % 256
            carry //= 256
            i += 1

        decoded_length = i
        source_offset += 1

    # Skip leading zeros in the decoded byte array
    decoded_offset = decoded_size - decoded_length
    while decoded_offset < decoded_size and decoded_bytes[decoded_offset] == 0:
        decoded_offset += 1

    # Create the final byte array that has been base-decoded
    final_bytes = bytearray(zeroes + (decoded_size - decoded_offset))
    j = zeroes
    while decoded_offset < decoded_size:
        final_bytes[j] = decoded_bytes[decoded_offset]
        j += 1
        decoded_offset += 1

    return final_bytes

# Example usage
import math

multibase_key = "z2eirz2eHx9vNB8uY8r81SUSU2dZop74ZUyEZEK5ZqXgoqYq4ujH7LqEZ3p57PYEwCdMZp72jAujcMx1RDbJzKBhB"
source_encoding = multibase_key[1:]
#identify base encoding algorithm from the first character of multibase key. for reference see https://github.com/multiformats/multibase/blob/master/multibase.csv
if multibase_key[0] == "z":
    source_base = 58
    base_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
if multibase_key[0] == "u":
    source_base = 64    
    base_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

decoded_bytes = base_decode(source_encoding, source_base, base_alphabet)
decoded_key = bytes(decoded_bytes)
#key_1 = decoded_key[2:34]
#hex_key = decoded_key.hex()
print(decoded_key)
print(len(decoded_key))
