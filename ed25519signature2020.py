import json
from pyld import jsonld
from hashlib import sha256
from base58 import b58decode, b58encode
from cryptography.hazmat.primitives.asymmetric import ed25519
import nacl.signing

# Define the key pair
#public_key_multibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
#private_key_multibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"

'''private_key = nacl.signing.SigningKey.generate()
public_key = private_key.verify_key
private_key_base58 = b58encode(private_key.encode())
public_key_base58 = b58encode(public_key.encode())'''

# Load the document
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
cannon = jsonld.normalize(document, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

# Hash canonized document
doc_hash = sha256(cannon.encode()).digest()
print(doc_hash.hex())

# Set proof options
proof_config = {
  "type": "Ed25519Signature2020",
  "created": "2023-02-24T23:36:38Z",
  "verificationMethod": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "proofPurpose": "assertionMethod",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ]
}

# Canonize the proof config
proof_canon = jsonld.normalize(proof_config, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

# Hash canonized proof config
proof_hash = sha256(proof_canon.encode()).digest()
print(proof_hash.hex())

# Combine hashes
combined_hash = proof_hash + doc_hash  # Hash order different from draft
print(combined_hash.hex())

# Sign
private_key = b'\x80&\xd0%\xbbW%\xbe\x90\x08\xa3\xf6\x1d\xd6>\xb1\xe2\xc7\x81D\x05\xabT\x9a\xfd\xc6T}v\xcd[_CJ' #b58decode(private_key_multibase)
private_key_r = private_key[2:34]
private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_r)
signature = private_key_obj.sign(combined_hash)
print(signature.hex())

# Verify (just to see we have a good private/public pair)
public_key = b'\xed\x01\x8c(\xe0\xe6{\x81M5\x15\x8b\xd4o\xc7F%oy^\xcd\xa7o\x8b3\x81\x9e\xb1\x9c?\x83-\xb8A' #b58decode(public_key_multibase)
public_key_r = public_key[2:34]
public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_r)
signature_encoded = b58encode(signature).decode()
print("signature_encoded", signature_encoded)
signature_decoded = b58decode(signature_encoded)
print("signature", signature_decoded)
result = public_key_obj.verify(signature_decoded, combined_hash)
'''try: 
  public_key_obj.verify(signature, combined_hash)
except Exception as GeneralException:
    err = str(GeneralException)
    if err == "Signature has expired":'''

# Construct Signed Document
signed_document = dict(document)
del proof_config['@context']
proof_config["proofValue"] = b58encode(signature).decode()
signed_document["proof"] = proof_config

print(json.dumps(signed_document, indent=2))
