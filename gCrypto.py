import os
import hmac
import hashlib
from Crypto.Cipher import AES


class AES_BASE:
    @staticmethod
    def pad(data: bytes) -> bytes:
        # Add padding to make the data length a multiple of AES block size (16 bytes)
        padding_length = AES.block_size - (len(data) % AES.block_size)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        # Remove padding added during encryption
        padding_length = data[-1]
        return data[:-padding_length]

    @staticmethod
    def generate_key(key_size: int) -> bytes:
        return os.urandom(key_size)

    @staticmethod
    def generate_iv() -> bytes:
        return os.urandom(AES.block_size)

    @staticmethod
    def hash_key(key: bytes, algorithm: str = 'sha1') -> str:
        hash_object = hashlib.new(algorithm)
        hash_object.update(key)
        return hash_object.hexdigest()


class AES_GCM(AES_BASE):
    @staticmethod
    def encrypt(data: bytes, header: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_GCM, iv)
        if header:
            cipher.update(header)
        return cipher.encrypt_and_digest(AES_GCM.pad(data))

    @staticmethod
    def decrypt(ciphertext: bytes, header: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_GCM, iv)
        if header:
            cipher.update(header)
        return AES_GCM.unpad(cipher.decrypt_and_verify(ciphertext, tag))


class AES_CBC(AES_BASE):
    @staticmethod
    def encrypt(data: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if pad:
            return cipher.encrypt(AES_CBC.pad(data))
        else:
            return cipher.encrypt(data)

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if pad:
            return AES_CBC.unpad(cipher.decrypt(ciphertext))
        else:
            return cipher.decrypt(ciphertext)



class HMAC():
    @staticmethod
    def sign(data: bytes, key: bytes, digestmod=hashlib.sha256, hexdigest=True) -> str:
        if hexdigest:
            return hmac.new(key, data, digestmod).hexdigest()
        else:
            return hmac.new(key, data, digestmod).digest()

    @staticmethod
    def verify(data: bytes, key: bytes, digest: bytes, digestmod=hashlib.sha256, hexdigest=True) -> bool:
        signed_digest = HMAC.sign(data, key, digestmod, hexdigest)
        return signed_digest == digest

