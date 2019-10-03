# AES 256 encryption/decryption using pycrypto library
# Programmed by The-Silent-1, using code from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html

import base64
import hashlib
import time
from Crypto.Cipher import AES
from Crypto import Random
import sys

def menu():
    print("AES256 Encryption & Decryption Script V1.0 \n")
    print("1. Encrypt a Message")
    print("2. Decrypt a Message")
    print("3. Exit \n")
    choice = input("Enter Your Choice (1,2,3): ")

    if choice == "1":
        EncryptMessage()

    if choice == "2":
        DecryptMessage()

    if choice == "3":
        sys.exit()

def EncryptMessage():
    # Encrypt secret message
    secretmessage = input("Enter plaintext: ")
    password = input("Enter Password: ")

    encrypted = encrypt(secretmessage, password)
    print(encrypted)

    time.sleep(2)
    another = False

    while another == False:
        print("")
        choice = input("Do you wish to encrypt another message? (Yes / No):")
        choice = choice.lower()

        if choice == "yes":
            another = True
        elif choice == "no":
            sys.exit()
        else:
            print("Invalid Input, please enter yes or no.")

    EncryptMessage()


def DecryptMessage():
    # Decrypt secret message
    secretmessage = input("Enter encrypted text: ")
    password = input("Enter Password: ")

    decrypted = decrypt(secretmessage, password)
    print(bytes.decode(decrypted))

    time.sleep(2)
    another = False

    while another == False:
        print("")
        choice = input("Do you wish to decrypt another message? (Yes / No)")
        choice = choice.lower()

        if choice == "yes":
            another = True
        elif choice == "no":
            sys.exit()
        else:
            print("Invalid Input, please enter yes or no.")

    DecryptMessage()

#AES Encryption & Decryption
#Code from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

menu()
