import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode



# Function to decode base64url encoded data
def base64url_decode(data):
    padded = data + b'=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)



# Generate a private key
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

# Extract the public key
public_key_r = private_key.public_key()

x = public_key_r.public_numbers().x
y = public_key_r.public_numbers().y

# Convert integers to bytes
x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
y_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')

# Encode bytes as Base64url
x_base64url = base64.urlsafe_b64encode(x_bytes).rstrip(b'=').decode('utf-8')
y_base64url = base64.urlsafe_b64encode(y_bytes).rstrip(b'=').decode('utf-8')

# Create the JWK object
jwk = {
    "kty": "EC",
    "crv": "secp256k1",
    "x": x_base64url,
    "y": y_base64url
}

print(jwk)

# Sample Verifiable Credential (payload)
vc = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://w3id.org/security/suites/jws-2020/v1"
    ],
    "id": "http://example.gov/credentials/3732",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": { "id": "did:example:123" },
    "issuanceDate": "2020-03-10T04:24:12.164Z",
    "credentialSubject": {
      "id": "did:example:456",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }
}

# Serialize the payload
payload = json.dumps(vc).encode()

# Sign the payload
signature = private_key.sign(
    payload,
    ec.ECDSA(hashes.SHA256())
)

# Base64url encode the signature
encoded_signature = urlsafe_b64encode(signature).decode().rstrip("=")

# Create the JWS header
jws_header = {
    "alg": "ES256K",
    "typ": "JWT"
}

# Serialize the JWS header
encoded_header = urlsafe_b64encode(json.dumps(jws_header).encode()).decode().rstrip("=")

# Assemble the JWS
jws = f"{encoded_header}.{urlsafe_b64encode(payload).decode().rstrip('=')}.{encoded_signature}"

print("JWS:", jws)

# Verify the JWS
decoded_header, decoded_payload, decoded_signature = jws.split(".")

decoded_signature += "=" * ((4 - len(decoded_signature) % 4) % 4)
decoded_signature_bytes = urlsafe_b64decode(decoded_signature.encode())

decoded_payload_bytes = urlsafe_b64decode(decoded_payload.encode())




# Decode the base64url encoded signature
signature_bytes = base64url_decode(encoded_signature.encode())

# Decode the base64url encoded x and y coordinates
x_bytes = base64url_decode(jwk['x'].encode())
y_bytes = base64url_decode(jwk['y'].encode())

# Concatenate the bytes with the prefix byte (0x04) to form the uncompressed point
point_bytes = b'\x04' + x_bytes + y_bytes

# Construct the elliptic curve public key
public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), point_bytes)






try:
    public_key.verify(
        decoded_signature_bytes,
        decoded_payload_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    print("Verification successful!")
except Exception as e:
    print("Verification failed:", e)


