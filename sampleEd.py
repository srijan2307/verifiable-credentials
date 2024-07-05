from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from base58 import b58decode


private_key = b'\x80&\xc9n\xf9\xea\x10\xc5\xe4\x14\xc4qr:\xff\x9d\xe7,5\xfa[p\xfa\xe9~\x882\xec\xac}.+\x8e\xd6' #b58decode(private_key_multibase)
private_key_r = private_key[2:34]
public_key = b'\xed\x01\xb0\r\x8d\x93\x8e\x7fw=QVZ\xad6\xa6#\xf54O\x7f]\x19`\xf9\xcf>\x8e\x12b\x0e\xa2\x81\x0f' #b58decode(public_key_multibase)
public_key_r = public_key[2:34]

private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_r)
public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_r)

# Message to be signed
message = b"Hello, world!"

# Sign the message
signature = private_key_obj.sign(message)

# Verify the signature
try:
    public_key_obj.verify(signature, message)
    print("Signature is valid.")
except InvalidSignature:
    print("Invalid signature.")
