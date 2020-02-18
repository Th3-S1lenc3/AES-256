# AES 256 encryption/decryption using pycryptodome library
# This file is for the GCM encryption & decryption algorithms
# Programmed by TH3_S1LENC3

from Cryptodome.Cipher import AES

def encryptString(plaintext, header, key):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def decryptString(ciphertext, header, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(header)
    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted, status = True
    except ValueError as mac_mismatch:
        print("MAC validation failed during decryption. No authentication garuntees on this ciphertext")
        print("Unauthenticated Associated Data: " + str(header))
        decrypted = ""
        return decrypted, status = False
    except KeyError:
        print("Incorrect Decryption Passphrase.")
        decrypted = ""
        return decrypted, status = False

def encryptFile(plaintext_file, key, salt):
    return "y"

def decryptFile():
    return "z"
