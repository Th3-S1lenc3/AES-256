# AES 256 encryption/decryption using pycryptodome library
# Programmed by TH3_S1LENC3

import getpass
import os
import base64
import hashlib
import time
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256 as sha256
from Cryptodome import Random
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import json
from base64 import b64encode, b64decode
import sys
import re

def menu():
    print("AES256 Encryption & Decryption Script Version 3.0 \n")
    print("1. Encrypt a String")
    print("2. Decrypt a String")
    print("3. Encrypt a File")
    print("4. Decrypt a File")
    print("5. ReadMe")
    print("6. Changelog")
    print("7. Exit \n")
    choice = input("Enter Your Choice [1,2,3,4,5,6,7]: ")

    if choice == "1":
        EncryptMessage()

    elif choice == "2":
        DecryptMessage()

    elif choice == "3":
        EncryptFile()

    elif choice == "4":
        DecryptFile()

    elif choice == "5":
        ReadMe()

    elif choice == "6":
        Changelog()

    elif choice == "7":
        sys.exit()

    else:
        print("Invalid Input. Please enter 1,2,3,4,5,6 or 7. \n")
        menu()


def EncryptMessage():
    # Get plaintext to encrypt
    secretmessage = input("Enter plaintext: ")
    # Get password
    password = getPassword()
    # Derive key from password and require 1gb of ram to do so
    salt = get_random_bytes(32)
    key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
    # Encrypt and print result
    encrypted = encrypt_message(secretmessage, key)
    print("Encrypted message: " + encrypted)
    print("Salt: " + salt)
    print("WARNING: If your salt is lost you will be unable to decrypt your message.")
    # -----------
    time.sleep(1)
    Continue()


def DecryptMessage():
    # Get encrypted text to decrypt
    secretmessage = input("Enter encrypted text: ")
    # Get password and salt
    password = getPassword()
    salt = getSalt()
    # Derive key from password and require 1gb of ram to do so
    key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
    # Decrypt and print result
    decrypted = decrypt_message(secretmessage, key)
    print(decrypted)
    # -----------
    time.sleep(1)
    Continue()


def EncryptFile():
    # Get file to encrypt
    filename = input("File to Encrypt: ")
    # Get password
    password = getPassword()
    # Generate key from password
    salt = get_random_bytes(32)
    key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
    encrypt_file(filename, key)
    print("Successfully encrypted: " + filename)
    print("Salt: " + salt)
    print("WARNING: If your salt is lost you will be unable to decrypt your message.")


def DecryptFile():
    # Get encrypted file to decrypt
    filename = input("File to Decrypt: ")
    # Get password and salt
    password = getPassword()
    salt = getSalt()
    # Generate key from password
    key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
    decrypt_file(filename, key)
    print("Successfully Decrypted: " + filename)

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
    # Asks the users if they wish to encrypt/decrypt another string
    choice = input("Do you wish to encrypt/decrypt another string (Yes/No): ")
    choice = choice.lower()

    if choice == "yes":
        menu()
    if choice == "no":
        os.system('cls' if os.name == 'nt' else 'clear')
        sys.exit(0)
    else:
        print("Please enter Yes or No. \n")
        Continue()

def getPassword():
    passwordsmatch = False
    while passwordsmatch == False:
        password = getpass.getpass("Enter Password: ")
        checkpassword = getpass.getpass("Re-enter Password: ")

        if password == checkpassword:
            result = CheckPassword(password)
            if result == True:
                print("Password does not meet criteria")
            else:
                passwordsmatch = True
        else:
            print("Error! Passwords do not match. Please try again!")
    return password


def CheckPassword(password):
    flag = 0
    while True:
        # Checks if password is less than 8
        if (len(password) < 8):
            flag = 1
            break
        # Checks if password contains lower case letters
        elif not re.search("[a-z]", password):
            flag = 2
            break
        # Checks if password contains upper case letters
        elif not re.search("[A-Z]", password):
            flag = 3
            break
        # Checks if password contains numbers
        elif not re.search("[0-9]", password):
            flag = 4
            break
        # Checks if password contains special characters
        elif not re.search("[_@$]", password):
            flag = 5
            break
        # Checks if password contains white spaces
        elif re.search("\s", password):
            flag = 6
            break
        # Else it meets criteria
        else:
            flag = 0
            break

    if flag == 1:
        print("Password Must Be 8 Characters")
        return(True)
    if flag == 2:
        print("Password Must Contain Lower Case ASCII Characters")
        return(True)
    if flag == 3:
        print("Password Must Contain Upper Case ASCII Characters")
        return(True)
    if flag == 4:
        print("Password Must Contain Numbers")
        return(True)
    if flag == 5:
        print("Password Must Contain Special Characters")
        return(True)
    if flag == 6:
        print("Password Must Not Contain Spaces")
        return(True)
    else:
        return(False)

def getSalt():
    salt = input("Enter salt: ")
    while re.search("\s" , salt) == True or salt[:2] != "b'":
        salt = input("Please enter a valid salt: ")
    bytes(salt, 'utf-8')
    return salt

# # Check that the the input file for encryption/decryption is not the same as the output files
# def check_file():
#     # assert get_file_hash(file_to_encrypt) == get_file_hash(file_to_encrypt + '.decrypted'), 'Files are not identical'
#
# def get_file_hash(file_path):
#     block_size = 65536
#     file_hash = hashlib.sha256()
#     with open(file_path, 'rb') as f:
#         fb = f.read(block_size)
#         while len(fb) > 0:
#             file_hash.update(fb)
#             fb = f.read(block_size)
#     return file_hash.hexdigest()

# AES Encryption & Decryption

def encrypt_message(secretmessage, key):
    # Convert secretmessage and key to bytes
    secretmessage = bytes(secretmessage, 'utf-8')
    key = bytes(key, 'utf-8')
    # Create a AES cipher object with the key using the mode CBC
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the input data and then encrypt
    ct_bytes = cipher.encrypt(pad(secretmessage, AES.block_size))
    # Return EncryptedText
    EncryptedText = b64encode(ct_bytes).decode('utf-8')
    return(EncryptedText)


def decrypt_message(enc, key):
    # Convert encrypted message and key to bytes
    enc = bytes(enc, 'utf-8')
    key = bytes(key, 'utf-8')
    # Create a AES cipher object with the key using the mode CBC
    cipher = AES.new(key, AES.MODE_CBC)
    # Unpad the encrypted message and decrypt
    DecryptedText = unpad(cipher.decrypt(enc), AES.block_size)
    # Return DecryptedText
    DecryptedText = DecryptedText.decode('utf-8')
    return(DecryptedText)

def encrypt_file(filename, key):
    # Open the input and output files
    file_to_encrypt = open(filename, 'rb')
    output_file = open(filename + '.encrypted', 'wb')
    # Set buffer_size
    buffer_size = 65536
    # Create the cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC)
    # Initially write the iv to the output file
    output_file.write(cipher.iv)
    # Keep reading the file into the buffer, encrypting then writing to the new file
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        ciphered_bytes = cipher.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)
    # Close the input and output files
    file_to_encrypt.close()
    output_file.close()

def decrypt_file(filename, key):
    # Open the input and output files
    # If file extention is included
    if filename[-10:] == '.encrypted':
        file_to_decrypt = open(filename, 'rb')
        output_file = open(filename[-10:] + '.decrypted', 'wb')
    # If file extention is not included
    else:
        file_to_decrypt = open(filename + '.encrypted', 'rb')
        output_file = open(filename + '.decrypted', 'wb')
    # Set buffer_size
    buffer_size = 65536
    # Get IV
    iv = file_to_decrypt.read(16)
    # Create the cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Initially write the iv to the output file
    output_file.write(iv)
    # Keep reading the file into the buffer, decrypting then writing to the new file
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        decrypted_bytes = cipher_encrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)
    # Close the input and output files
    file_to_decrypt.close()
    output_file.close()
    check_file()

menu()
