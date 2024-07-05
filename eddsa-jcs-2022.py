import json
from hashlib import sha256
from base58 import b58encode, b58decode
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives.asymmetric import ed25519
import nacl.signing

# Define the key pair
#publicKeyMultibase = b"z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
#privateKeyMultibase = b"z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"

private_generate = nacl.signing.SigningKey.generate()
public_generate = private_generate.verify_key
privateKeyMultibase = b58encode(private_generate.encode())
publicKeyMultibase = b58encode(public_generate.encode())

# Read input document from a file or just specify it right here.
document = {
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
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod"
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
private_key = b58decode(privateKeyMultibase)#[4:]
signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
signature = signing_key.sign(combined_hash)
print("Computed Signature from private key:")
print(signature.hex())

# Verify (just to see we have a good private/public pair)
public_key = b58decode(publicKeyMultibase)#[4:]
verify_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
result = verify_key.verify(signature, combined_hash)
print(f"Signature verified: {result}")

# Construct Signed Document
signed_document = document.copy()
proof_config["proofValue"] = b58encode(signature).decode()
signed_document["proof"] = proof_config

print(json.dumps(signed_document, indent=2))
