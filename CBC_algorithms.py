# AES 256 encryption/decryption using pycryptodome library
# This file is for the CBC encryption & decryption algorithms
# Programmed by TH3_S1LENC3

from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encryptString(plaintext, key):
    # Convert plaintext and key to bytes
    plaintext = bytes(plaintext, 'utf-8')
    key = bytes(key, 'utf-8')
    # Create a AES cipher object
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the input data and encrypts
    ct_bytes = cipher.encrypt(pad(secretmessage, AES.block_size))
    # Return EncryptedText & IV
    IV = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ct_bytes).decode('utf-8')
    ciphertext = IV + ciphertext
    return ciphertext

def decryptString(ciphertext, key):
    # Convert encrypted message and key to bytes
    ciphertext = bytes(ciphertext, 'utf-8')
    key = bytes(key, 'utf-8')
    # Get IV
    iv = ciphertext[:16]
    # Create a AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        # Unpad the encrypted message and decrypt
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        # Return DecryptedText
        return decrypted, status = True
    except ValueError:
        print("ValueError")
        decrypted = ""
        return decrypted, status = False
    except KeyError:
        print("Invalid Decryption Passphrase.")
        decrypted = ""
        return decrypted, status = False

def encryptFile():
    return "y"

def decryptFile():
    return "z"
