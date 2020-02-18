# AES 256 encryption/decryption using pycrypto library
# Programmed by TH3_S1LENC3 using code from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html

import getpass
import os
import base64
import hashlib
import time
from Cryptodome.Cipher import AES
from Cryptodome import Random
import sys
import re

def menu():
    print("AES256 Encryption & Decryption Script Version 2.1 \n")
    print("1. Encrypt a Message")
    print("2. Decrypt a Message")
    print("3. ReadMe")
    print("4. Changelog")
    print("5. Exit \n")
    choice = raw_input("Enter Your Choice [1,2,3,4,5]: ")

    if choice == "1":
        EncryptMessage()

    if choice == "2":
        DecryptMessage()

    if choice == "3":
        ReadMe()

    if choice == "4":
        Changelog()

    if choice == "5":
        sys.exit()

    else:
        print("Invalid Input. Please enter 1, 2, 3, or 4. \n")
        menu()

def EncryptMessage():
    # Encrypt secret message
    secretmessage = raw_input("Enter plaintext: ")
    passwordsmatch = False
    while passwordsmatch == False:
        password = getpass.getpass("Enter Password: ")
        checkpassword = getpass.getpass("Re-enter Password: ")

        if password == checkpassword:
            CheckPassword(password)
            if CheckPassword == True:
                print("Password does not meet criteria")
            else:
                encrypted = encrypt(secretmessage, password)
                print(encrypted)
                passwordsmatch = True
                break
        else:
            print("Error! Passwords do not match. Please try again!")
    time.sleep(1)
    Continue()

def DecryptMessage():
    # Decrypt secret message
    secretmessage = raw_input("Enter encrypted text: ")
    passwordsmatch = False
    while passwordsmatch == False:
        password = getpass.getpass("Enter Password: ")
        checkpassword = getpass.getpass("Re-enter Password: ")

        if password == checkpassword:
            CheckPassword(password)
            if CheckPassword == True:
                print("Password does not meet criteria")
            else:
                decrypted = decrypt(secretmessage, password)
                print(bytes.decode(decrypted))
                passwordsmatch = True
                break
        else:
            print("Error! Passwords do not match. Please try again!")
    time.sleep(1)
    Continue()

def ReadMe():
    with open("README.md") as f:
        print("")
        print(f.read())
        time.sleep(5)
        menu()

def Changelog():
    with open("Changelog.txt") as f:
        print("")
        print(f.read())
        time.sleep(5)
        menu()

def Continue():
    # Asks the users if they wish to encrypt/decrypt another file
    choice = raw_input("Do you wish to encrypt/decrypt another file (Yes/No): ")
    choice = choice.lower()

    if choice == "yes":
        menu()
    if choice == "no":
        os.system('cls' if os.name == 'nt' else 'clear')
        sys.exit(0)
    else:
        print("Please enter Yes or No. \n")
        Continue()

def CheckPassword(password):
    flag = 0
    while True:
        if (len(password)<8):
            flag = -1
            break
        elif not re.search("[a-z]", password):
            flag = -2
            break
        elif not re.search("[A-Z]", password):
            flag = -3
            break
        elif not re.search("[0-9]", password):
            flag = -4
            break
        elif not re.search("[_@$]", password):
            flag = -5
            break
        elif re.search("\s", password):
            flag = -6
            break
        else:
            flag = 0
            break

    if flag == -1:
        print("Password Must Be 8 Characters")
        return True
    if flag == -2:
        print("Password Must Contain Lower Case ASCII Characters")
        return True
    if flag == -3:
        print("Password Must Contain Upper Case ASCII Characters")
        return True
    if flag == -4:
        print("Password Must Contain Numbers")
        return True
    if flag == -5:
        print("Password Must Contain Special Characters")
        return True
    if flag == -6:
        print("Password Must Not Contain Spaces")
        return True
    else:
        return False


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
