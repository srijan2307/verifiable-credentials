import json
import math
from hashlib import sha256
from base58 import b58encode, b58decode
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives.asymmetric import ed25519
import nacl.signing

# Define the key pair
publicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
privateKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"

'''private_generate = nacl.signing.SigningKey.generate()
public_generate = private_generate.verify_key
privateKeyMultibase = b58encode(private_generate.encode())
publicKeyMultibase = b58encode(public_generate.encode())'''


def base_decode(source_encoding):
    source_base = 58
    base_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
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

#Decode the private key
source_encoding_private = privateKeyMultibase[1:]
decoded_bytes_private = base_decode(source_encoding_private)
private_key = bytes(decoded_bytes_private)
private_key_r = private_key[2:34]

#Decode the public key
source_encoding_public = publicKeyMultibase[1:]
decoded_bytes_public = base_decode(source_encoding_public)
public_key = bytes(decoded_bytes_public)
print(public_key)
exit()
public_key_r = public_key[2:34]

# Read input document from a file or just specify it right here.
document = {
    "@context": "https://www.w3.org/2018/credentials/v1",
    "holder": "did:web:demo-apps.dl6.in:user:fd6bb3d779419968ec5552121a95cd7c",
    "type": "VerifiablePresentation",
    "verifiableCredential": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "credentialSubject": {
            "docIssuerName": "Income Tax Department",
            "docName": "PAN Card",
            "docType": "PANCR",
            "id": "did:web:demo-apps.dl6.in:user:810fe844-abb3-534e-9757-d60a2a8cd98c"
        },
        "issuanceDate": "2024-04-03T22:18:23+05:30",
        "issuer": "did:web:demo-apps.dl6.in:issuers:in.gov.pan",
        "type": [
            "VerifiableCredential",
            "PanCredential"
        ]
    }
}

# Canonize the document
cannon = encode_canonical_json(document)
print("Canonized unsigned document:")
print(cannon)

# Hash canonized document
doc_hash = sha256(cannon).digest()
print("Hash of canonized document in hex:")
print(doc_hash.hex())

# Set proof options per draft
proof_config = {
    "created": "2024-04-03T22:18:23+05:30",
    "cryptosuite": "eddsa-jcs-2022",
    "id": "74738c51-92e9-44d4-9d12-7d294f270e04",
    "proofPurpose": "authentication",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:web:demo-apps.dl6.in:users:fd6bb3d779419968ec5552121a95cd7c#f817dd6a9734f6ab70cd525929ad2e29"
}

# Canonize the proof config
proof_canon = encode_canonical_json(proof_config)
print("Proof Configuration Canonized:")
print(proof_canon)

# Hash canonized proof config
proof_hash = sha256(proof_canon).digest()
print("Hash of canonized proof in hex:")
print(proof_hash.hex())

# Combine hashes
combined_hash = proof_hash + doc_hash  # Hash order different from draft
print("Combined Hash in hex:")
print(combined_hash.hex())


# Sign
#private_key = b58decode(privateKeyMultibase)#[4:]
signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_r)
signature = signing_key.sign(combined_hash)
print("Computed Signature from private key:")
print(signature.hex())

# Verify (just to see we have a good private/public pair)
#public_key = b58decode(publicKeyMultibase)#[4:]
verify_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_r)
result = verify_key.verify(signature, combined_hash)
print(f"Signature verified: {result}")

# Construct Signed Document
signed_document = document.copy()
proof_config["proofValue"] = b58encode(signature).decode()
signed_document["proof"] = proof_config

print(json.dumps(signed_document, indent=2))
