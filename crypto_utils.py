from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.publickey().export_key().decode(), key.export_key().decode()


def encrypt_file(file_bytes):
    aes_key = get_random_bytes(32)  # 32 bytes = AES-256
    cipher = AES.new(aes_key, AES.MODE_EAX)
    encrypted_file, tag = cipher.encrypt_and_digest(file_bytes)
    # The tag is needed to detect tampering. We store nonce + tag together.
    return aes_key, encrypted_file, cipher.nonce, tag


def decrypt_file(aes_key, encrypted_file, nonce, tag):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plain_bytes = cipher.decrypt(encrypted_file)
    cipher.verify(tag)
    return plain_bytes


def encrypt_aes_key(aes_key, receiver_public_key):
    public_key = RSA.import_key(receiver_public_key)
    return PKCS1_OAEP.new(public_key).encrypt(aes_key)


def decrypt_aes_key(encrypted_key, receiver_private_key):
    private_key = RSA.import_key(receiver_private_key)
    return PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
